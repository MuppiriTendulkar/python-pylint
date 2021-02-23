# Property of the National Bank of Canada. All Rights Reserved.

WIKI = 'https://wiki.bnc.ca/x/dwQkNQ'

# Testing for wide Egress HTTPS is too flaky
# Thightly coupled with https://git.bnc.ca/projects/CLOUDSEC/repos/aws-security-group/browse/known_cidr_blocks.yaml?at=refs%2Fheads%2Fdevelop#740
# from netaddr import *
# IPSet(['0.0.0.0/0']) - IPSet(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
# VALID_INTERNET_CIDR = ('0.0.0.0/5', '8.0.0.0/7', '11.0.0.0/8', '12.0.0.0/6', '16.0.0.0/4', '32.0.0.0/3', '64.0.0.0/2', '128.0.0.0/3', '160.0.0.0/5', '168.0.0.0/6', '172.0.0.0/12', '172.32.0.0/11', '172.64.0.0/10', '172.128.0.0/9', '173.0.0.0/8', '174.0.0.0/7', '176.0.0.0/4', '192.0.0.0/9', '192.128.0.0/11', '192.160.0.0/13', '192.169.0.0/16', '192.170.0.0/15', '192.172.0.0/14', '192.176.0.0/12', '192.192.0.0/10', '193.0.0.0/8', '194.0.0.0/7', '196.0.0.0/6', '200.0.0.0/5', '208.0.0.0/4', '224.0.0.0/3')

import ipaddress
import boto3
import importlib
from helper import ConfigItemEvaluation, get_logger, adjust_tag_value, InapplicableConfigItemEvaluation


# TODO The following check is not implemented yet:
# - Has to be attached to only one type of resource

log = get_logger()

def evaluate_compliance_item_Change(event, credentials, configuration_item):
    # TODO This control is not enabled yet
    return [ InapplicableConfigItemEvaluation(configuration_item, event) ]
    securityhub_resource_details = {
        'GroupName': configuration_item['configuration']['groupName'],
        'GroupId': configuration_item['configuration']['groupId'],
        'OwnerId': configuration_item['configuration']['ownerId'],
        'VpcId': configuration_item['configuration']['vpcId'],
        # TODO IpPermissions keys start with uppercase
        # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-attributes.html#asff-resourcedetails-awsec2securitygroup
        # 'IpPermissions': configuration_item['configuration']['ipPermissions'],
        # 'IpPermissionsEgress': configuration_item['configuration']['ipPermissionsEgress']
    }
    eval = ConfigItemEvaluation(__name__, configuration_item, WIKI, event, 'AwsEc2SecurityGroup', securityhub_resource_details)
    # TODO This control is not enabled yet
    # return [eval]
    # log = get_logger()
    vpc_control = importlib.import_module('controls.AWS_EC2_VPC')
    compliant_vpcs = vpc_control.list_compliant_vpcs()
    is_attached = False
    for relation in configuration_item["relationships"]:
        if relation['resourceType'] == 'AWS::EC2::VPC' and relation['resourceId'] not in compliant_vpcs:
            eval.add_finding('MEDIUM', 'Security Group is in a non-compliant VPC', 'This CloudSec control checks for existance of Security Groups in a non-compliant VPCs.')
        if relation['resourceId'][0:3] == "eni":
            is_attached = True
    if not is_attached:
        eval.add_finding('LOW', 'Security Group is not attached', 'This CloudSec control checks for existance of Security Groups that are not associated with any Amazon Elastic Network Interface')

    for permission in configuration_item['configuration']['ipPermissions']:
        # log.debug(f"Ingress permission: {permission}")
        if len(permission['ipv6Ranges']) > 0:
            eval.add_finding('LOW', 'IPv6 is not allowed', 'This CloudSec control checks for existance of IPv6 in Security Groups')
        # log.debug(f"Ingress ipv4Ranges: {permission['ipv4Ranges']}")
        for ip_range in permission['ipv4Ranges']:
            cidr = ipaddress.ip_network(ip_range['cidrIp'])
            if cidr.prefixlen < 16 and ip_range['cidrIp'] != '10.0.0.0/8':
                eval.add_finding('MEDIUM', 'Security Group Ingress CIDR too wide', 'This CloudSec control checks for existance of Security Groups Ingress CIDR wider than /16 other than 10.0.0.0/8')
        if permission['ipProtocol'] == 'tcp' and ((permission['fromPort'] <= 22 and permission['toPort'] >= 22) or (permission['fromPort'] <= 3389 and permission['toPort'] >= 3389)):
            for ip_range in permission['ipv4Ranges']:
                cidr = ipaddress.ip_network(ip_range['cidrIp'])
                if cidr.prefixlen < 32 and ip_range['cidrIp'] != '10.0.0.0/8':
                    eval.add_finding('MEDIUM', 'SSH or RDP from forbidden sources',  'This CloudSec control checks for existance of Security Group Ingress SSH or RDP that are not from 10.0.0.0/8 or single IPs')
    for permission in configuration_item['configuration']['ipPermissionsEgress']:
        # log.debug(f"Egress permission: {permission}")
        if len(permission['ipv6Ranges']) > 0:
            eval.add_finding('LOW', 'IPv6 is not allowed', 'This CloudSec control checks for existance of IPv6 in Security Groups')
        # log.debug(f"Egress ipv4Ranges: {permission['ipv4Ranges']}")
        for ip_range in permission['ipv4Ranges']:
            cidr = ipaddress.ip_network(ip_range['cidrIp'])
            if cidr.prefixlen < 16 and ip_range['cidrIp'] != '10.0.0.0/8':
                if permission['ipProtocol'] != 'tcp' or permission['fromPort'] != 443 or permission['toPort'] != 443:
                    eval.add_finding('MEDIUM', 'Non-HTTPS egress to internet is not allowed', 'This CloudSec control checks for existance of Security Groups Egress CIDR wider than /16 other than 10.0.0.0/8 for non-HTTPS traffic')
                # Testing for wide Egress HTTPS is too flaky
                # elif ip_range['cidrIp'] not in VALID_INTERNET_CIDR:
                #     eval.add_finding('CRITICAL', 'Security Group Egress CIDR too wide', 'This CloudSec control checks for existance of Security Groups Egress CIDR wider than /16 other than 10.0.0.0/8 and IPSet(["0.0.0.0/0"]) - IPSet(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])')

    return [eval]


def remediate(finding, credentials):
    if finding['Compliance']['Status'] == 'NOT_AVAILABLE':
        log.debug("There is nothing to do for this finding")
        return True
    sg_client = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken']
                                )
    if finding['Compliance']['Status'] == 'PASSED':
        sg_client.delete_tags( Resources=[finding['ProductFields']['ResourceId']], Tags=[{'Key': finding['Title']}] )
        return True
    sg_client.create_tags( Resources=[finding['ProductFields']['ResourceId']], Tags=[{'Key': finding['Title'], 'Value': adjust_tag_value(finding['SourceUrl'], finding['Description'])}] )
    return True
