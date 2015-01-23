#!/usr/bin/env python
"""
Import utility for terraform state
Reads resource IDs from AWS account, generates terraform.tfstate

Copyright 2015 Splunk, Inc.
All rights reserved

created by rich braun <rbraun@splunk.com> 12-Jan-2015

  AWS credentials as environment variables (from ~/.cr) or specified as
  aws_import.py --credentials=ec2_creds.cfg
"""

import argparse
import copy
import json
import logging
import os
import sys

import boto.ec2
import boto.ec2.elb
import boto.iam.connection
import boto.route53
import boto.s3.connection
import boto.vpc
import ConfigParser

RES_TYPES = [
    'eip', 'elb', 'iam_group', 'iam_role', 'iam_user', 'internet_gateway',
    'key_pair', 'network_acl', 'route_table', 'route53_record', 'route53_zone',
    's3_bucket', 'security_group', 'subnet', 'vpc']
UNIMPLEM_TYPES = ['iam_group', 'iam_role', 'iam_user']

arg_parser = argparse.ArgumentParser(description="AWS import utility")
arg_parser.add_argument('--output-file', '-o',
                        default='aws.tf',
                        help='Output file')
arg_parser.add_argument('--state-file', '-f',
                        default='terraform.tfstate',
                        help='State file')
arg_parser.add_argument('--config-name',
                        default='primary',
                        help='Configuration name')
arg_parser.add_argument('--resource', choices=RES_TYPES,
                        action='append', help='AWS resource type')
arg_parser.add_argument('--exclude', choices=RES_TYPES,
                        action='append', help='AWS resource types to exclude')
arg_parser.add_argument('--ignore-auth-errors', action='store_true',
                        help='Ignore unauthorized resource types')
arg_parser.add_argument('--inactive', action='store_true',
                        help='Include stopped/terminated instances')
arg_parser.add_argument('--credentials', '-c',
                        help='Credentials file, see ec2_creds.cfg.sample')
arg_parser.add_argument('--aws-access-key-id', '-a',
                        default=os.environ['AWS_ACCESS_KEY_ID'],
                        help='AWS access key')
arg_parser.add_argument('--aws-secret-access-key', '-s',
                        default=os.environ['AWS_SECRET_ACCESS_KEY'],
                        help='AWS secret')
arg_parser.add_argument('--aws-account',
                        help='AWS account')
arg_parser.add_argument('--aws-region', default='us-east-1',
                        help='AWS region')
if __name__ == '__main__':
    args = arg_parser.parse_args()


class Resource:
    """
    Class to fetch AWS resources and handle Terraform files
    """

    def __init__(self, connection,
                 ignore_auth_errors=False,
                 include_inactive=False,
                 config_name='primary'):
        """Constructor for Terraform resource connection to AWS"""

        self.connection = connection
        self.syslog = logging.getLogger()
        handler = logging.handlers.SysLogHandler(
            address=('/var/run/syslog' if sys.platform == 'darwin'
                     else '/dev/log'),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL1)
        self.syslog.addHandler(handler)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        self.syslog.addHandler(console)
        self.syslog.setLevel(logging.INFO)
        self.ignore_auth_errors = ignore_auth_errors
        self.include_inactive = include_inactive
        self.config_name = config_name
        self.resource_map = {}
        try:
            self.aws_account = (connection['iam'].get_user(
            )['get_user_response']['get_user_result'][
                'user']['arn'].split(':')[4])
        except boto.exception.BotoServerError:
            self.aws_account = None

    def gather_resources(self, resource_type):
        """Gather all specified resources from AWS API"""

        result = {}
        if resource_type == 'eip':
            for ip in self.connection['ec2'].get_all_addresses():
                if ip.instance_id or self.include_inactive:
                    if ip.instance_id:
                        inst = self.connection['ec2'].get_only_instances(
                            [ip.instance_id])
                        resname = (inst[0].tags['Name'] or
                                   ip.public_ip.replace('.', '_'))
                        result[resname] = {
                            'attributes': {
                                'instance': ip.instance_id
                            }
                        }
                    else:
                        resname = ip.public_ip.replace('.', '_')
                        result[resname] = {}
                    result[resname]["id"] = ip.public_ip
        elif resource_type == 'block_device':
            pass
            '''
            # Not implemented, block_devices need to be under instances
            # and that's only useful if you want Terraform to manage
            # instances
            for item in self.connection['ec2'].get_all_volumes():
                if item.status != 'available' or self.include_inactive:
                    result[item.id] = {
                        'encrypted': str(item.encrypted),
                        'size': str(item.size),
                        'type': item.type
                    }
                    if item.iops:
                        result[item.id]['iops'] = item.iops
                    if item.snapshot_id:
                        result[item.id]['snapshot_id'] = item.snapshot_id
                    result[resname]["attributes"] = (
                        self.aws_read_tags(result[resname]["attributes"],
                        item))
                    result[resname]["id"] = item.id
            '''
        elif resource_type == 'elb':
            for item in sorted(self.connection['elb'].get_all_load_balancers(),
                               key=lambda v: v.name):
                listener = []
                for iter in item.listeners:
                    tup1, tup2, tup3, tup4 = iter.get_complex_tuple()
                    listener.append({
                        'lb_port': str(tup1),
                        'instance_port': str(tup2),
                        'lb_protocol': tup3.lower(),
                        'instance_protocol': tup4.lower()
                    })
                    if iter.ssl_certificate_id:
                        listener[-1]['ssl_certificate_id'] = (
                            iter.ssl_certificate_id)
                resname = item.name
                result[resname] = {
                    'attributes': {
                        'health_check': {
                            'healthy_threshold': str(
                                item.health_check.healthy_threshold),
                            'interval': str(item.health_check.interval),
                            'target': item.health_check.target,
                            'timeout': str(item.health_check.timeout),
                            'unhealthy_threshold': str(
                                item.health_check.unhealthy_threshold)
                        },
                        'listeners': listener,
                        'name': item.name
                    }
                }
                if item.subnets:
                    result[resname]["attributes"]["subnets"] = item.subnets
                else:
                    result[resname]["attributes"]["availability_zones"] = (
                        item.availability_zones)
                result[resname]["id"] = item.name
        elif resource_type == 'iam_group':
            try:
                groups = self.connection['iam'].get_all_groups(
                ).list_groups_response.list_groups_result.groups
            except boto.exception.BotoServerError:
                groups = []
                if not self.ignore_auth_errors:
                    raise boto.exception.BotoServerError
            for item in groups:
                resname = item.group_name
                result[resname] = {
                    'attributes': {
                        'arn': item.arn,
                        'name': item.group_name,
                        'path': item.path
                    }
                }
                result[resname]["id"] = item.group_id
        elif resource_type == 'iam_role':
            try:
                roles = self.connection['iam'].list_roles(
                ).list_roles_response.list_roles_result.roles
            except boto.exception.BotoServerError:
                roles = []
                if not self.ignore_auth_errors:
                    raise boto.exception.BotoServerError
            for item in roles:
                resname = item.role_name
                result[resname] = {
                    'attributes': {
                        'arn': item.arn,
                        'name': item.role_name,
                        'path': item.path,
                        'policy': item.assume_role_policy_document,
                    }
                }
                result[resname]["id"] = item.role_id
        elif resource_type == 'iam_user':
            try:
                users = self.connection['iam'].get_all_users(
                ).list_users_response.list_users_result.users
            except boto.exception.BotoServerError:
                users = []
                if not self.ignore_auth_errors:
                    raise boto.exception.BotoServerError
            for item in users:
                resname = item.user_name
                result[resname] = {
                    'attributes': {
                        'arn': item.arn,
                        'name': item.user_name,
                        'path': item.path
                    }
                }
                result[resname]["id"] = item.user_id
        elif resource_type == 'internet_gateway':
            for item in self.connection['vpc'].get_all_internet_gateways():
                resname = self.aws_get_name(item) or item.id
                if item.attachments:
                    result[resname] = {
                        'attributes': {
                            'vpc_id': item.attachments[0].vpc_id
                        }
                    }
                else:
                    result[resname] = {}
                result[resname]["id"] = item.id
        elif resource_type == 'key_pair':
            for keypair in sorted(self.connection['ec2'].get_all_key_pairs(),
                                  key=lambda pair: pair.name):
                resname = keypair.name.replace(' ', '_')
                result[resname] = {
                    'attributes': {
                        'key_name': keypair.name,
                        'public_key': 'please-insert-manually'
                    }
                }
                result[resname]["id"] = keypair.name
        elif resource_type == 'network_acl':
            for item in self.connection['vpc'].get_all_network_acls():
                resname = self.aws_get_name(item) or item.id
                result[resname] = {
                    'attributes': {
                        'vpc_id': item.vpc_id
                    }
                }
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 'route53_record':
            pass
            '''
            # Not implemented, not using Terraform for DNS yet
            for item in self.connection['route53'].get_all_rrsets():
                result[item.id] = None
            '''
        elif resource_type == 'route53_zone':
            api = self.connection['route53'].get_all_hosted_zones()
            for item in api['ListHostedZonesResponse']['HostedZones']:
                resname = item['Name'].replace('.', '_')
                result[resname] = {
                    'attributes': {
                        'name': item['Name']
                    }
                }
                result[resname]["id"] = item['Id']
        elif resource_type == 'route_table':
            for item in self.connection['vpc'].get_all_route_tables():
                resname = self.aws_get_name(item) or item.id
                result[resname] = {
                    'attributes': {
                        'vpc_id': item.vpc_id,
                        'routes': []
                    }
                }
                for route in item.routes:
                    if route.gateway_id == 'local':
                        continue
                    result[resname]['attributes']['routes'].append({
                        'cidr_block': route.destination_cidr_block
                    })
                    if route.gateway_id:
                        result[resname]['attributes'][
                            'routes'][-1]['gateway_id'] = route.gateway_id
                    if route.instance_id:
                        result[resname]['attributes'][
                            'routes'][-1]['instance_id'] = route.instance_id
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 's3_bucket':
            for item in self.connection['s3'].get_all_buckets():
                resname = item.name
                result[resname] = {
                    'attributes': {
                        'bucket': item.name,
                        'acl': 'private'
                    }
                }
                result[resname]["id"] = item.name
        elif resource_type == 'subnet':
            for item in self.connection['vpc'].get_all_subnets():
                resname = self.aws_get_name(item) or item.id
                result[resname] = {
                    'attributes': {
                        'availability_zone': item.availability_zone,
                        'cidr_block': item.cidr_block,
                        'map_public_ip_on_launch': item.mapPublicIpOnLaunch,
                        'vpc_id': item.vpc_id
                    }
                }
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 'security_group':
            for item in self.connection['vpc'].get_all_security_groups():
                resname = (self.aws_get_name(item) or
                           item.name.replace(' ', '_'))
                if resname == 'default':
                    continue
                result[resname] = {
                    'attributes': {
                        'name': item.name,
                        'description': item.description,
                        'vpc_id': item.vpc_id
                    }
                }
                ingress = []
                egress = []
                for rule in item.rules:
                    ingress.append({
                        'protocol': rule.ip_protocol,
                        'from_port': rule.from_port or 0,
                        'to_port': rule.to_port or 0
                    })
                    grps = []
                    cidrs = []
                    for grant in rule.grants:
                        if (grant == "%s-%s" % (resname, self.aws_account)
                                or grant.group_id == item.id):
                            ingress[-1]['self'] = 'true'
                        elif grant.cidr_ip:
                            cidrs.append(grant.cidr_ip)
                        else:
                            grps.append(grant.group_id)
                    if grps:
                        ingress[-1]['security_groups'] = grps
                    if cidrs:
                        if grps:
                            ingress.append({
                                'protocol': rule.ip_protocol,
                                'from_port': rule.from_port or 0,
                                'to_port': rule.to_port or 0
                            })
                        ingress[-1]['cidr_blocks'] = cidrs
                for rule in item.rules_egress:
                    egress.append({
                        'protocol': rule.ip_protocol,
                        'from_port': rule.from_port or 0,
                        'to_port': rule.to_port or 0
                    })
                    grps = []
                    cidrs = []
                    for grant in rule.grants:
                        if (grant == "%s-%s" % (resname, self.aws_account)
                                or grant.group_id == item.id):
                            egress[-1]['self'] = 'true'
                        elif grant.cidr_ip:
                            cidrs.append(grant.cidr_ip)
                        else:
                            grps.append(grant.group_id)
                    if grps:
                        egress[-1]['security_groups'] = grps
                    if cidrs:
                        if grps:
                            egress.append({
                                'protocol': rule.ip_protocol,
                                'from_port': rule.from_port or 0,
                                'to_port': rule.to_port or 0
                            })
                        egress[-1]['cidr_blocks'] = cidrs
                if len(ingress):
                    result[resname]['attributes']['ingress'] = ingress
                if len(egress):
                    result[resname]['attributes']['egress'] = egress
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 'vpc':
            for item in self.connection['vpc'].get_all_vpcs():
                resname = self.aws_get_name(item) or item.id
                result[resname] = {
                    'attributes': {
                        'cidr_block': item.cidr_block,
                        'instance_tenancy': item.instance_tenancy
                    }
                }
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        else:
            raise SyntaxError('Resource type %s not recognized' %
                              resource_type)
        return result

    def aws_get_name(self, item):
        """Fetch AWS tag "Name" if it exists"""
        if item.tags and 'Name' in item.tags:
            return item.tags['Name'].replace(' ', '_')

    def aws_read_tags(self, item, obj):
        """Read AWS tags into a dict, merging into any existing attributes."""
        result = None
        if obj.tags:
            result = {"tags": {}}
            for tag, val in obj.tags.items():
                if tag[:4] == 'aws:':
                    tag = tag.replace('aws:', 'aws-', 1)
                result["tags"][tag] = val
        if item and result:
            return dict(item.items() + result.items())
        else:
            return item or result

    def tfstate_entry(self, resource_type, definition, name):
        desc = {"id": definition["id"]}
        if "attributes" in definition:
            desc["attributes"] = definition["attributes"]
        self.resource_map["%s.%s" % (resource_type, definition['id'])] = (
            "aws_%s.%s.id" % (resource_type, name))
        return {"type": "aws_%s" % resource_type,
                self.config_name: desc}

    def tfresource_entry(self, item, name):
        if "tags" in item and "Name" in item["tags"]:
            res_name = item["tags"]["Name"].replace(' ', '_')
        else:
            res_name = name[name.find('.') + 1:].replace('.', '_')

        if item['type'][4:] in UNIMPLEM_TYPES:
            result = "#resource \"%s\" \"%s\" {\n" % (item['type'], res_name)
            result += "#  (Not yet implemented in Terraform)\n"
            result += "#}\n"
            return result

        result = "resource \"%s\" \"%s\" {\n" % (item['type'], res_name)
        if "attributes" in item[self.config_name]:
            for key, val in sorted(item[self.config_name]
                                   ["attributes"].items()):
                if key == 'tags':
                    result += "    %s {\n" % key
                    for k, v in val.items():
                        result += "        \"%s\" = \"%s\"\n" % (
                            k, v.replace('"', '\\"'))
                    result += "    }\n"
                elif key == 'health_check':
                    result += "    %s {\n" % key
                    for k, v in val.items():
                        result += "        %s = \"%s\"\n" % (k, v)
                    result += "    }\n"
                # Note - as of 1/20/2015, terraform doesn't yet support
                #   egress rules, commenting those out
                # elif key in ['egress', 'ingress']:
                elif key in ['ingress']:
                    for iter in val:
                        result += "    %s {\n" % key
                        for k, v in iter.items():
                            if k == 'protocol':
                                v = "\"%s\"" % v
                            elif k in ['security_groups', 'cidr_blocks']:
                                v = "[\"%s\"]" % "\",\"".join(map(str, v))
                            '''
                            elif k == 'grants':
                                if len(v) == 0:
                                    continue
                                if v[0].cidr_ip:
                                    k = 'cidr_blocks'
                                else:
                                    k = 'security_groups'
                                v = "[\"%s\"]" % "\",\"".join(map(str, v))
                            '''
                            result += "        %s = %s\n" % (k, v)
                        result += "    }\n"

                # Temporary commenting-out egress
                elif key in ['egress']:
                    for iter in val:
                        result += "#   %s {\n" % key
                        for k, v in iter.items():
                            if k == 'protocol':
                                v = "\"%s\"" % v
                            elif k == 'grants':
                                if len(v) == 0:
                                    continue
                                if str(v[0])[0] in '0123456789':
                                    k = 'cidr_blocks'
                                else:
                                    k = 'security_groups'
                                v = "[\"%s\"]" % "\",\"".join(map(str, v))
                            result += "#       %s = %s\n" % (k, v)
                        result += "#   }\n"

                elif key in ['listeners', 'routes']:
                    for iter in val:
                        result += "    %s {\n" % key[:-1]
                        for k, v in iter.items():
                            result += "        %s = \"%s\"\n" % (k, v)
                        result += "    }\n"
                elif key == 'subnets' or key == 'availability_zones':
                    result += "    %s = [\"%s\"]\n" % (key, '", "'.join(val))
                else:
                    result += "    %s = \"%s\"\n" % (key, val)
        result += "}\n"
        return result

    def tfvariables(self, vars):
        """Generate variable definitions"""
        result = ""
        for varname, content in sorted(vars.items()):
            if content:
                result += "variable \"%s\" {\n" % varname
                result += "    default = {\n"
                for key, val in content.items():
                    result += "        %s = \"%s\"\n" % (key, val)
                result += "    }\n}\n"
            else:
                result += "variable \"%s\" {}\n" % varname
        result += "\n"
        return result

    def strip_arrays(self, obj):
        """
        When generating an initial tfstate file, any nested arrays
        have to be stripped out and populated by 'terraform refresh';
        also remove unimplemented resource types
        """
        new = copy.deepcopy(obj)
        for key, resource in new["modules"][0]["resources"].items():
            if resource['type'][4:] in UNIMPLEM_TYPES:
                del new["modules"][0]["resources"][key]

            elif "attributes" in resource[self.config_name]:
                for k in resource[self.config_name]["attributes"].keys():
                    if k in ['availability_zones', 'egress', 'health_check',
                             'ingress', 'listeners', 'routes', 'subnets',
                             'tags']:
                        del resource[self.config_name]["attributes"][k]
        return new

    def update_dependencies(self, obj, vars):
        """
        Look up AWS ID-specific items, and update them into Terraform
        resource-name dependencies
        """
        for key, resource in obj["modules"][0]["resources"].items():
            res_type = resource['type'][4:]
            if res_type in ['internet_gateway', 'network_acl', 'route_table',
                            'security_group', 'subnet']:
                try:
                    resource[self.config_name]['attributes']['vpc_id'] = (
                        "${%s}" % self.resource_map["vpc.%s" % resource[
                            self.config_name]['attributes']['vpc_id']])
                except KeyError:
                    pass
            if res_type == 'route_table':
                for route in resource[self.config_name][
                        'attributes']['routes']:
                    try:
                        route['gateway_id'] = (
                            "${%s}" % self.resource_map["internet_gateway.%s" %
                                                   route['gateway_id']])
                    except KeyError:
                        pass
            if res_type == 'elb':
                for k, subnet in enumerate(
                        resource[self.config_name]['attributes']['subnets']):
                    resource[self.config_name]['attributes']['subnets'][k] = (
                        "${%s}" % self.resource_map["subnet.%s" % subnet])
                if 'ssl_cert_arn' in vars:
                    for listener in resource[self.config_name][
                            'attributes']['listeners']:
                        try:
                            listener['ssl_certificate_id'] = (
                                listener['ssl_certificate_id'].replace(
                                    vars['ssl_cert_arn']['prefix'],
                                    "${var.ssl_cert_arn.prefix}"))
                        except KeyError:
                            pass
            if res_type == 'security_group':
                entries = []
                if 'ingress' in resource[self.config_name]['attributes']:
                    entries += resource[self.config_name]['attributes'][
                        'ingress']
                if 'egress' in resource[self.config_name]['attributes']:
                    entries += resource[self.config_name]['attributes'][
                        'egress']
                for perm in entries:
                    if 'security_groups' not in perm:
                        continue
                    for k, grp in enumerate(perm['security_groups']):
                        try:
                            perm['security_groups'][k] = ("${%s}" %
                                self.resource_map["security_group.%s" % grp])
                        except KeyError:
                            pass
            if res_type == 'subnet':
                try:
                    resource[self.config_name]['attributes'][
                        'availability_zone'] = (
                            "${var.zones.%s}" % vars['zones'].keys()[
                            list(vars['zones'].values()).index(
                            resource[self.config_name]['attributes'][
                            'availability_zone'])])
                except KeyError:
                    pass

    def get_aws_account(self):
        return self.aws_account

    def set_aws_account(self, account):
        self.aws_account = account

    def get_aws_name(self):
        try:
            return self.connection['iam'].get_account_alias(
            ).list_account_aliases_response.list_account_aliases_result.\
                account_aliases[0]
        except (KeyError, boto.exception.BotoServerError):
            return None


def main():
    if args.credentials:
        config_file = "%s/%s" % (os.path.dirname(
            os.path.realpath(__file__)), args.credentials)

        config = ConfigParser.ConfigParser()
        config.read(config_file)
        aws_access_key = config.get('aws', 'aws_access_key', 0)
        aws_secret_key = config.get('aws', 'aws_secret_key', 0)
    else:
        aws_access_key = args.aws_access_key_id
        aws_secret_key = args.aws_secret_access_key

    # Create connection with AWS
    awsconn = {}
    awsconn['ec2'] = boto.ec2.connect_to_region(
        args.aws_region,
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key)

    resource_list = args.resource or RES_TYPES
    if args.exclude:
        for item in args.exclude:
            resource_list.remove(item)

    awsconn['iam'] = boto.iam.connection.IAMConnection(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key)

    # ELB, Route53, VPC require different connection types
    if 'elb' in resource_list:
        awsconn['elb'] = boto.ec2.elb.ELBConnection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if 'route53_record' in resource_list:
        awsconn['route53'] = boto.route53.Route53Connection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if 's3_bucket' in resource_list:
        awsconn['s3'] = boto.s3.connection.S3Connection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if 'vpc' in resource_list:
        awsconn['vpc'] = boto.vpc.VPCConnection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)

    res = Resource(awsconn, args.ignore_auth_errors, args.inactive,
                   args.config_name)

    # Build two data structures:
    #  'obj' is the main tree of AWS resources
    #  'resource_map' is a mapping from resource ID to Terraform
    #    names, for dependency mapping (see
    #    https://www.terraform.io/intro/getting-started/dependencies.html)
    aws_account = args.aws_account or res.get_aws_account()
    res.set_aws_account(aws_account)
    aws_name = res.get_aws_name()
    obj = {
        "version": 1,
        "serial": 1,
        "modules": [{
            "path": [
                "root"
            ],
            "outputs": {},
            "account_info": {
                "aws_account": aws_account,
                "aws_name": aws_name
            },
            "resources": {}
        }]
    }

    for resource in resource_list:
        a = res.gather_resources(resource)
        for key in a.keys():
            obj["modules"][0]["resources"]["aws_%s.%s" % (
                resource, key)] = res.tfstate_entry(resource, a[key], key)

    # Generate the terraform.tfstate file from obj
    fd = os.open(args.state_file, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(res.strip_arrays(obj), sort_keys=True, indent=4))
    f.close()

    # Update dependencies
    variables = {
        'access_key': {},
        'secret_key': {},
        'zones': {
            'zone0': args.aws_region + "a",
            'zone1': args.aws_region + "b",
            'zone2': args.aws_region + "c",
            'zone3': args.aws_region + "d",
            'zone4': args.aws_region + "e"
        }
    }
    if aws_account:
        variables['ssl_cert_arn'] = {
            'prefix': "arn:aws:iam::%s:server-certificate" % aws_account
        }
    res.update_dependencies(obj, variables)

    # Generate the resource definitions file
    fd = os.open(args.output_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
    with os.fdopen(fd, 'w') as f:

        f.write(res.tfvariables(variables))

        f.write("provider \"aws\" {\n    region = \"%s\"\n" % args.aws_region)
        f.write("    access_key = \"%s\"\n" % "${var.access_key}")
        f.write("    secret_key = \"%s\"\n" % "${var.secret_key}")
        if aws_account:
            f.write("#    account = \"%s\"\n" % aws_account)
        if aws_name:
            f.write("#    name = \"%s\"\n" % aws_name)
        f.write("}\n\n")

        for key, item in sorted(obj["modules"][0]["resources"].items()):
            f.write(res.tfresource_entry(item, key))
    f.close()


if __name__ == '__main__':
    main()
