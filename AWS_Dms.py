# Property of the National Bank of Canada. All Rights Reserved.
#
# As of 2021 Feb 7, most of DMS is not supported as a Type for ASFF Resources
# https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-attributes.html#asff-resources

WIKI = 'https://wiki.bnc.ca/x/g6SHM'

import json
import boto3
from helper import Evaluation, get_logger, adjust_tag_value

# The DMS Endpoint source engine does not have ssl_mode options/requirement
ENDPOINTS_SSLMODE_ENGINE_EXCEPTION = ['Amazon S3', 'Amazon DynamoDB', 'Amazon Kinesis', 'Amazon Neptune', 'Amazon Redshift', 'Elasticsearch Service', 'Kafka']

log = get_logger()


def resource_types():
    return (
        'AWS::DMS::Endpoint',
        'AWS::DMS::ReplicationTask',
        'AWS::DMS::ReplicationInstance',
    )


def evaluate_compliance_scheduled(event, credentials):
    dms_client = boto3.client('dms', aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken']
                                )
    return evaluate_endpoint(event, dms_client) + evaluate_replication_task(event, dms_client) + evaluate_replication_instances(event, dms_client)


def evaluate_endpoint(event, dms_client):
    log.debug('Evaluating DMS Endpoints')
    evaluations = []
    dms_response = dms_client.describe_endpoints()
    for endpoint in dms_response.get('Endpoints', []):
        eval = Evaluation(__name__, 'AWS::DMS::Endpoint', endpoint['EndpointIdentifier'], endpoint['EndpointArn'], WIKI, event)  # no resource_timestamp available
        # if ssl_mode not applicable
        if endpoint['EngineDisplayName'] not in ENDPOINTS_SSLMODE_ENGINE_EXCEPTION and endpoint['SslMode'] == 'none':
            eval.add_finding('HIGH', 'DMS Endpoint does not have SSL enabled', 'This CloudSec control checks that SSL is enabled for Source and Target DMS Endpoints.')
        evaluations.append(eval)
    return evaluations


def evaluate_replication_task(event, dms_client):
    log.debug('Evaluating DMS ReplicationTasks')
    evaluations = []
    dms_response = dms_client.describe_replication_tasks()
    for task in dms_response.get('ReplicationTasks', []):
        eval = Evaluation(__name__, 'AWS::DMS::ReplicationTask', task['ReplicationTaskIdentifier'], task['ReplicationTaskArn'], WIKI, event, task['ReplicationTaskCreationDate'].isoformat())
        task_settings = json.loads(task['ReplicationTaskSettings'])
        if not task_settings['Logging']['EnableLogging']:
            eval.add_finding('MEDIUM', 'CloudWatch Logging is not enabled on DMS Task', 'This CloudSec control checks that CloudWatch Logging is enabled on DMS ReplicationTasks.')
        evaluations.append(eval)
    return evaluations


def evaluate_replication_instances(event, dms_client):
    log.debug('Evaluating DMS ReplicationInstance')
    evaluations = []
    dms_response = dms_client.describe_replication_instances()
    for instance in dms_response.get('ReplicationInstances', []):
        eval = Evaluation(__name__, 'AWS::DMS::ReplicationInstance', instance['ReplicationInstanceIdentifier'], instance['ReplicationInstanceArn'], WIKI, event, instance['InstanceCreateTime'].isoformat(), 'AwsDmsReplicationInstance')
        if instance['PubliclyAccessible']:
            eval.add_finding('CRITICAL', 'Public DMS Replication Instance is not allowed', 'This CloudSec control checks that DMS Replication Instance are not Public.')
        if not instance['AutoMinorVersionUpgrade']:
            eval.add_finding('MEDIUM', 'Auto minor version upgrade is not enabled on DMS Replication Instance', 'This CloudSec control checks that auto minor version upgrade is enabled on DMS Replication Instance.')
        evaluations.append(eval)
    return evaluations


def remediate(finding, credentials):
    if finding['Compliance']['Status'] == 'NOT_AVAILABLE':
        log.debug(f"There is nothing to do for this finding")
        return True
    dms_client = boto3.client('dms', aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken']
                                )
    if finding['Compliance']['Status'] == 'PASSED':
        dms_client.remove_tags_from_resource( ResourceArn=finding['ProductFields']['ResourceArn'], TagKeys=[finding['Title']] )
        return True
    dms_client.add_tags_to_resource( ResourceArn=finding['ProductFields']['ResourceArn'], Tags=[{'Key': finding['Title'], 'Value': adjust_tag_value(finding['SourceUrl'], finding['Description'])}] )
    return True
