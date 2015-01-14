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
import json
import logging
import os
import sys

import boto.ec2
import boto.ec2.elb
import boto.route53
import boto.s3.connection
import boto.vpc
import ConfigParser

RES_TYPES = [
    'eip', 'elb', 'internet_gateway', 'key_pair',
    'network_acl', 'route_table', 'route53_record', 'route53_zone',
    's3_bucket', 'security_group', 'subnet', 'vpc']

arg_parser = argparse.ArgumentParser(description="AWS import utility")
arg_parser.add_argument('--output-file', '-o',
                        default='aws.tf',
                        help='Output file')
arg_parser.add_argument('--state-file', '-f',
                        default='terraform.tfstate',
                        help='State file')

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

    def __init__(self, connection, include_inactive):
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

    def list_resources(self, resource_type):
        result = {}
        if resource_type == 'eip':
            for ip in self.connection['ec2'].get_all_addresses():
                if ip.instance_id or self.include_inactive:
                    result[ip.public_ip] = None
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
                    if item.tags:
                        result[item.id] = self.aws_read_tags(result[item.id],
                                                             item)
            '''
        elif resource_type == 'elb':
            for item in sorted(self.connection['elb'].get_all_load_balancers(),
                               key=lambda v: v.name):
                listener = []
                for iter in item.listeners:
                    tup1, tup2, tup3 = iter.get_tuple()
                    listener.append({
                        'lb_port': tup1,
                        'instance_port': tup2,
                        'lb_protocol': tup3,
                        'instance_protocol': tup3
                    })
                result[item.name] = {
                    'availability_zones': item.availability_zones,
                    'health_check': {
                        'healthy_threshold':
                        str(item.health_check.healthy_threshold),
                        'interval': str(item.health_check.interval),
                        'target': item.health_check.target,
                        'timeout': str(item.health_check.timeout),
                        'unhealthy_threshold':
                        str(item.health_check.unhealthy_threshold)
                    },
                    'listeners': listener,
                    'name': item.name
                }
                if item.subnets:
                    result[item.name]['subnets'] = item.subnets
        elif resource_type == 'internet_gateway':
            for item in self.connection['vpc'].get_all_internet_gateways():
                result[item.id] = None
        elif resource_type == 'key_pair':
            for keypair in sorted(self.connection['ec2'].get_all_key_pairs(),
                                  key=lambda pair: pair.name):
                result[keypair.name] = {
                    'key_name': keypair.name,
                    'public_key': 'not_implemented'
                }
        elif resource_type == 'network_acl':
            for item in self.connection['vpc'].get_all_network_acls():
                result[item.id] = {
                    'vpc_id': item.vpc_id
                }
                result[item.id] = self.aws_read_tags(result[item.id], item)
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
                result[item['Id']] = {
                    'name': item['Name']
                }
        elif resource_type == 'route_table':
            for item in self.connection['vpc'].get_all_route_tables():
                result[item.id] = {
                    'vpc_id': item.vpc_id
                }
                result[item.id] = self.aws_read_tags(result[item.id], item)
        elif resource_type == 's3_bucket':
            for item in self.connection['s3'].get_all_buckets():
                result[item.name] = {
                    'bucket': item.name
                }
        elif resource_type == 'subnet':
            for item in self.connection['vpc'].get_all_subnets():
                result[item.id] = {
                    'cidr_block': item.cidr_block
                }
                result[item.id] = self.aws_read_tags(result[item.id], item)
        elif resource_type == 'security_group':
            for item in self.connection['vpc'].get_all_security_groups():
                result[item.id] = {
                    'name': item.name,
                    'description': item.description
                }
                result[item.id] = self.aws_read_tags(result[item.id], item)
        elif resource_type == 'vpc':
            for item in self.connection['vpc'].get_all_vpcs():
                result[item.id] = {
                    'cidr_block': item.cidr_block
                }
                result[item.id] = self.aws_read_tags(result[item.id], item)
        else:
            raise SyntaxError('Resource type %s not recognized' %
                              resource_type)
        return result

    # Read AWS tags into a dict with Terraform's syntax, merging into
    # any existing attributes.  tags.# is set to the number of tags
    # and the tags attributes are tags.<key>.
    def aws_read_tags(self, item, obj):
        result = None
        if obj.tags:
            result = {"tags.#": str(len(obj.tags))}
            for tag, val in obj.tags.items():
                result["tags.%s" % tag] = val
        if item and result:
            return dict(item.items() + result.items())
        else:
            return item or result

    def tfstate_entry(self, resource_type, resource_key, attrs):
        desc = {"id": resource_key}
        if attrs:
            desc["attributes"] = attrs
        return {"type": "aws_%s" % resource_type,
                "primary": desc}

    def tfresource_entry(self, item, name):
        if "tags" in item and "Name" in item["tags"]:
            res_name = item["tags"]["Name"].replace(' ', '_')
        else:
            res_name = name[name.find('.') + 1:].replace('.', '_')
        result = "resource \"%s\" \"%s\" {\n" % (item['type'], res_name)
        if "attributes" in item["primary"]:
            do_tags = False
            for key, val in sorted(item["primary"]["attributes"].items()):
                if key[0:4] == 'tags':
                    do_tags = True
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
            if do_tags:
                result += "    tags {\n"
                for key, val in sorted(item["primary"]["attributes"].items()):
                    if key[0:4] == 'tags' and key != 'tags.#':
                        result += "        \"%s\" = \"%s\"\n" % (key[5:], val)
                result += "    }\n"
        result += "}\n"
        return result


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

    res = Resource(awsconn, args.inactive)

    obj = {
        "version": 1,
        "serial": 1,
        "modules": [{
            "path": [
                "root"
            ],
            "outputs": {},
            "resources": {}
        }]
    }

    resources = [args.resource] if args.resource else RES_TYPES
    for resource in resources:
        a = res.list_resources(resource)
#        for key, item in res.list_resources(resource):
#            obj["modules"][0]["resources"]["aws_%s.%s" % (
#                    resource, key)] = res.tfstate_entry(resource, key, item)
        for key in a.keys():
            obj["modules"][0]["resources"]["aws_%s.%s" % (
                resource, key)] = res.tfstate_entry(resource, key,
                                                    a[key])
    fd = os.open(args.state_file, os.O_CREAT | os.O_RDWR | os.O_EXCL)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(obj, sort_keys=True, indent=4))
    f.close()
    fd = os.open(args.output_file, os.O_CREAT | os.O_RDWR)
    with os.fdopen(fd, 'w') as f:
        f.write("provider \"aws\" {\n    region = \"%s\"\n" % args.aws_region)
        f.write("}\n\n")
        for key, item in sorted(obj["modules"][0]["resources"].items()):
            f.write(res.tfresource_entry(item, key))
    f.close()


if __name__ == '__main__':
    main()
