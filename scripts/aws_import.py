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
#    'eip', 'elb', 'iam_group', 'iam_role', 'iam_user', 'internet_gateway',
    'eip', 'elb', 'internet_gateway',
    'key_pair', 'network_acl', 'route_table', 'route53_record', 'route53_zone',
    's3_bucket', 'security_group', 'subnet', 'vpc']

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
                        help='AWS resource type')
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
arg_parser.add_argument('--aws-region', default='us-east-1',
                        help='AWS region')
args = arg_parser.parse_args()


class Resource:
    """
    Class to fetch AWS resources and handle Terraform files
    """

    def __init__(self, connection, include_inactive, config_name):
        self.connection = connection
        self.syslog = logging.getLogger()
        handler = logging.handlers.SysLogHandler(
            address='/var/run/syslog' if sys.platform == 'darwin' else '/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_LOCAL1)
        self.syslog.addHandler(handler)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        self.syslog.addHandler(console)
        self.syslog.setLevel(logging.INFO)
        self.include_inactive = include_inactive
        self.config_name = config_name

    # Gather all specified resources from AWS API
    def gather_resources(self, resource_type):
        result = {}
        if resource_type == 'eip':
            for ip in self.connection['ec2'].get_all_addresses():
                if ip.instance_id or self.include_inactive:
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
                        self.aws_read_tags(result[resname]["attributes"], item))
                    result[resname]["id"] = item.id
            '''
        elif resource_type == 'elb':
            for item in sorted(self.connection['elb'].get_all_load_balancers(),
                               key=lambda v: v.name):
                listener = []
                for iter in item.listeners:
                    tup1, tup2, tup3 = iter.get_tuple()
                    listener.append({
                        'lb_port': str(tup1),
                        'instance_port': str(tup2),
                        'lb_protocol': tup3,
                        'instance_protocol': tup3
                    })
                resname = item.name
                result[resname] = {
                    'attributes': {
                        'availability_zones': item.availability_zones,
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
                result[resname]["id"] = item.name
        elif resource_type == 'iam_group':
            for item in self.connection['iam'].get_all_groups(
            ).list_groups_response.list_groups_result.groups:
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
            for item in self.connection['iam'].list_roles(
            ).list_roles_response.list_roles_result.roles:
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
            for item in self.connection['iam'].get_all_users(
            ).list_users_response.list_users_result.users:
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
                resname = item.id
                result[resname] = {}
                result[resname]["id"] = item.id
        elif resource_type == 'key_pair':
            for keypair in sorted(self.connection['ec2'].get_all_key_pairs(),
                                  key=lambda pair: pair.name):
                resname = keypair.name.replace(' ', '_')
                result[resname] = {
                    'attributes': {
                        'key_name': keypair.name,
                        'public_key': 'not_implemented'
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
                resname = item['Name']
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
                        'vpc_id': item.vpc_id
                    }
                }
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 's3_bucket':
            for item in self.connection['s3'].get_all_buckets():
                resname = item.name
                result[resname] = {
                    'attributes': {
                        'bucket': item.name
                    }
                }
                result[resname]["id"] = item.name
        elif resource_type == 'subnet':
            for item in self.connection['vpc'].get_all_subnets():
                resname = self.aws_get_name(item) or item.id
                result[resname] = {
                    'attributes': {
                        'availability_zone': item.availability_zone,
                        'cidr_block': item.cidr_block
                    }
                }
                result[resname]["attributes"] = (
                    self.aws_read_tags(result[resname]["attributes"], item))
                result[resname]["id"] = item.id
        elif resource_type == 'security_group':
            for item in self.connection['vpc'].get_all_security_groups():
                resname = (self.aws_get_name(item) or 
                           item.name.replace(' ', '_'))
                result[resname] = {
                    'attributes': {
                        'name': item.name,
                        'description': item.description
                    }
                }
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

    # Fetch AWS tag "Name" if it exists
    def aws_get_name(self, item):
        if item.tags and 'Name' in item.tags:
            return item.tags['Name'].replace(' ', '_')

    # Read AWS tags into a dict, merging into any existing attributes.
    def aws_read_tags(self, item, obj):
        result = None
        if obj.tags:
            result = {"tags": {}}
            for tag, val in obj.tags.items():
                result["tags"][tag] = val
        if item and result:
            return dict(item.items() + result.items())
        else:
            return item or result

    def tfstate_entry(self, resource_type, definition):
        desc = {"id": definition["id"]}
        if "attributes" in definition:
            desc["attributes"] = definition["attributes"]
        return {"type": "aws_%s" % resource_type,
                self.config_name: desc}

    def tfresource_entry(self, item, name):
        if "tags" in item and "Name" in item["tags"]:
            res_name = item["tags"]["Name"].replace(' ', '_')
        else:
            res_name = name[name.find('.') + 1:].replace('.', '_')
        result = "resource \"%s\" \"%s\" {\n" % (item['type'], res_name)
        if "attributes" in item[self.config_name]:
            for key, val in sorted(item[self.config_name]
                                   ["attributes"].items()):
                if key == 'tags':
                    result += "    %s {\n" % key
                    for k, v in val.items():
                        result += "        \"%s\" = \"%s\"\n" % (k, v)
                    result += "    }\n"
                elif key == 'health_check':
                    result += "    %s {\n" % key
                    for k, v in val.items():
                        result += "        %s = \"%s\"\n" % (k, v)
                    result += "    }\n"
                elif key == 'listeners':
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

    # When generating an initial tfstate file, any nested arrays
    # have to be stripped out and populated by 'terraform refresh'
    def strip_arrays(self, obj):
        new = copy.deepcopy(obj)
        for key, resource in new["modules"][0]["resources"].items():
            if "attributes" in resource[self.config_name]:
                for k in resource[self.config_name]["attributes"].keys():
                    if k in ['availability_zones', 'health_check',
                             'listeners', 'subnets', 'tags']:
                        del resource[self.config_name]["attributes"][k]
        return new


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

    # ELB, Route53, VPC require different connection types
    if args.resource == 'elb' or args.resource is None:
        awsconn['elb'] = boto.ec2.elb.ELBConnection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if args.resource == 'iam_role' or args.resource is None:
        awsconn['iam'] = boto.iam.connection.IAMConnection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if args.resource == 'route53_record' or args.resource is None:
        awsconn['route53'] = boto.route53.Route53Connection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if args.resource == 's3_bucket' or args.resource is None:
        awsconn['s3'] = boto.s3.connection.S3Connection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)
    if args.resource == 'vpc' or args.resource is None:
        awsconn['vpc'] = boto.vpc.VPCConnection(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key)

    res = Resource(awsconn, args.inactive, args.config_name)

    obj = {
        "version": 1,
        "serial": 1,
        "modules": [{
            "path": [
                "root"
            ],
            "outputs": {},
            "account_info": {
                "aws_account": awsconn['iam'].get_user(
                )['get_user_response']['get_user_result']['user']
                ['arn'].split(':')[4],
                "aws_name": awsconn['iam'].get_account_alias(
                ).list_account_aliases_response.list_account_aliases_result.account_aliases[0]
            },
            "resources": {}
        }]
    }

    resources = [args.resource] if args.resource else RES_TYPES
    for resource in resources:
        a = res.gather_resources(resource)
        for key in a.keys():
            obj["modules"][0]["resources"]["aws_%s.%s" % (
                resource, key)] = res.tfstate_entry(resource, a[key])
    fd = os.open(args.state_file, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(res.strip_arrays(obj), sort_keys=True, indent=4))
    f.close()
    fd = os.open(args.output_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC )
    with os.fdopen(fd, 'w') as f:
        f.write("provider \"aws\" {\n    region = \"%s\"\n" % args.aws_region)
        f.write("    access_key = \"%s\"\n" % "${var.access_key}")
        f.write("    secret_key = \"%s\"\n" % "${var.secret_key}")
        f.write("#    account = \"%s\"\n" % obj["modules"][0]
                ["account_info"]["aws_account"])
        f.write("#    name = \"%s\"\n" % obj["modules"][0]
                ["account_info"]["aws_name"])
        f.write("}\n\n")
        for key, item in sorted(obj["modules"][0]["resources"].items()):
            f.write(res.tfresource_entry(item, key))
    f.close()


if __name__ == '__main__':
    main()
