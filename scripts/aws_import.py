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
import boto.vpc
import ConfigParser

RES_TYPES=[
    'ebs', 'eip', 'elb', 'internet_gateway', 'key_pair',
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
    Class to fetch resources
    """

    def __init__(self, connection, include_inactive, config_name):
        self.connection = connection
        self.syslog = logging.getLogger()
        handler = logging.handlers.SysLogHandler(
            address='/var/run/syslog' if sys.platform=='darwin' else '/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_LOCAL1)
        self.syslog.addHandler(handler)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        self.syslog.addHandler(console)
        self.syslog.setLevel(logging.INFO)
        self.include_inactive = include_inactive
        self.config_name = config_name

    def list_resources(self, resource_type):
        result = {}
        if resource_type=='eip':
            for ip in self.connection['ec2'].get_all_addresses():
                if ip.instance_id or self.include_inactive:
                    result[ip.public_ip] = None
        elif resource_type=='ebs':
            for item in self.connection['ec2'].get_all_volumes():
                if item.status != 'available' or self.include_inactive:
                    result[item.id] = None
        elif resource_type=='elb':
            for elb in sorted(self.connection['elb'].get_all_load_balancers(),
                              key=lambda v: v.name):
                result[elb.name] = None
        elif resource_type=='internet_gateway':
            for item in self.connection['vpc'].get_all_internet_gateways():
                result[item.id] = None
        elif resource_type=='key_pair':
            for keypair in sorted(self.connection['ec2'].get_all_key_pairs(),
                                  key=lambda pair: pair.name):
                result[keypair.name] = {
                    'fingerprint': keypair.fingerprint
                    }
        elif resource_type=='network_acl':
            for item in self.connection['vpc'].get_all_network_acls():
                result[item.id] = None
#        elif resource_type=='route53_record':
#            for item in self.connection['route53'].get_all_rrsets():
#                result[item.id] = None
        elif resource_type=='route53_zone':
            api = self.connection['route53'].get_all_hosted_zones()
            for item in api['ListHostedZonesResponse']['HostedZones']:
                result[item['Id']] = {
                    'name': item['Name']
                    }
        elif resource_type=='route_table':
            for item in self.connection['vpc'].get_all_route_tables():
                result[item.id] = None
        elif resource_type=='s3_bucket':
            for item in self.connection['vpc'].get_all_route_tables():
                result[item.id] = None
        elif resource_type=='subnet':
            for item in self.connection['vpc'].get_all_subnets():
                result[item.id] = {
                    'cidr_block': item.cidr_block
                    }
        elif resource_type=='security_group':
            for item in self.connection['vpc'].get_all_security_groups():
                result[item.id] = None
        elif resource_type=='vpc':
            for item in self.connection['vpc'].get_all_vpcs():
                result[item.id] = {
                    'cidr_block': item.cidr_block
                    }
#        else:
#            raise SyntaxError('Resource type %s not recognized' % resource_type)
        return result

    def tfstate_entry(self, resource_type, resource_key, attrs):
        desc = { "id": resource_key }
        if attrs:
            desc["attributes"] = attrs
        return { "aws_%s.%s" % (resource_type, self.config_name):
                     { "type": "aws_%s" % resource_type,
                       "primary": desc
                       }
               }

        
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
    if args.resource=='elb' or args.resource==None:
        awsconn['elb'] = boto.ec2.elb.ELBConnection(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key)
    if args.resource=='route53_record' or args.resource==None:
        awsconn['route53'] = boto.route53.Route53Connection(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key)
    if args.resource=='vpc' or args.resource==None:
        awsconn['vpc'] = boto.vpc.VPCConnection(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key)

    res = Resource(awsconn, args.inactive, 'infra_%s' % args.aws_region)

    obj = {
      "version": 1,
      "serial": 1,
      "modules": [ {
          "resources": {}
          } ]
    }

    resources = [ args.resource ] if args.resource else RES_TYPES
    for resource in resources:
        a = res.list_resources(resource)
#        for key, item in res.list_resources(resource):
#            obj["modules"][0]["resources"]["aws_%s.%s" % (
#                    resource, key)] = res.tfstate_entry(resource, key, item)
        for key in a.keys():
            obj["modules"][0]["resources"]["aws_%s.%s" % (
                    resource, key)] = res.tfstate_entry(resource, key,
                                                        a[key])
    fd = os.open(args.state_file, os.O_CREAT|os.O_RDWR|os.O_EXCL)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(obj, sort_keys=True, indent=4))

if __name__ == '__main__':
    main()
