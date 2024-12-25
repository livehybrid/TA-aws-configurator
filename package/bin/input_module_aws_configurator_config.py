# encoding = utf-8

import os
import sys
import time
import datetime
import splunk.rest
import splunk.entity as entity
import splunklib.client as client
import solnlib.splunk_rest_client as src
import solnlib.utils as sutils

import json

from aws_helper import aws_helper


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # aws_description_role_name = definition.parameters.get('aws_description_role_name', None)
    pass


def collect_events(helper, ew):
    helper.set_log_level("info")
    config_username = 'audit_config'

    splunk_session_key = helper.context_meta['session_key']


    rest_client = src.SplunkRestClient(
        session_key=splunk_session_key, app='Splunk_TA_aws', owner='nobody', scheme='https', host='localhost',
        port=8089)

    aws = aws_helper(helper, rest_client)

    ta_creds = list(aws.get_app_credentials(splunk_session_key, "*", "Splunk_TA_aws"))
    incremental_sqs_definitions = aws.get_incremental_sqs_definitions()

    helper.log_info("Retrieved count={} credentials".format(len(ta_creds)))

    config_role_arn = helper.get_arg('aws_config_role_arn')
    aws.configure_ta_cred(config_username, config_role_arn, ta_creds)


    service_definition = aws.find_in_dict(incremental_sqs_definitions, 'name', 'config_audit_snapshot')
    service_endpoint = 'splunk_ta_aws_aws_sqs_based_s3'
    service_config = {
        "name": 'config_audit_snapshot',
        "aws_account": "SplunkLoader-AWS",
        "aws_iam_role": config_username,
        "interval" : "60",
        "sqs_batch_size" : "10",
        "s3_file_decoder" : "Config",
        "sqs_queue_url" : helper.get_arg('aws_config_sqs_url'),
        "sqs_queue_region" : helper.get_arg('aws_config_sqs_region'),
        "sourcetype": "aws:config",
        "index": helper.get_output_index()
    }

    aws.configure_service(service_config, service_endpoint, service_definition)


    input_type = helper.get_input_type()
    event = helper.new_event(source=input_type, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(),
                             data="Finished configuring IAM Roles and inputs")
    ew.write_event(event)

    helper.log_warning("END")
    exit(0)

