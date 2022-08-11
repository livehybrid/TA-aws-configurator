# encoding = utf-8

import os
import sys
import time
import datetime
import splunk.rest
import splunk.entity as entity
import splunklib.client as client
import solnlib.splunk_rest_client as src

import json

from aws_helper import aws_helper


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # aws_description_role_name = definition.parameters.get('aws_description_role_name', None)
    pass


def get_description_definitions(helper, rest_client):
    response = rest_client.get(
        'splunk_ta_aws_aws_description', owner='nobody', app='Splunk_TA_aws',
        output_mode='json', count=-1)
    if response.status not in (200, 201):
        helper.log_error("Failed to query", endpoint='splunk_ta_aws_aws_description', reason=response.reason)
        raise Exception("Failed to query endpoint {}".format(response))
    return json.loads(response.body.read())['entry']




def collect_events(helper, ew):
    from pprint import pformat
    helper.set_log_level("info")
    # helper.rest_helper.send_http_request
    #
    splunk_session_key = helper.context_meta['session_key']

    rest_client = src.SplunkRestClient(
        session_key=splunk_session_key, app='Splunk_TA_aws', owner='nobody', scheme='https', host='localhost',
        port=8089)
    aws = aws_helper(helper, rest_client)

    ta_creds = list(aws.get_app_credentials(splunk_session_key, "*", "Splunk_TA_aws"))
    description_definitions = get_description_definitions(helper, rest_client)

    helper.log_info("Retrieved count={} credentials".format(len(ta_creds)))

    assumed_session = aws.aws_session(role_arn=helper.get_global_setting("root_org_role_arn"),
                                            session_name='org_lookup')
    org_accounts = aws.get_orgs(assumed_session)

    #check for any configs that are no longer in the org list...to detect deleted roles/accounts
    for description_definition in description_definitions:
        description_name = description_definition['name']
        if "_audit" in description_name:
            description_accountid = description_name.replace("_audit","")
            if not description_accountid in [org_account['Id'] for org_account in org_accounts]:
                helper.log_info("Account not found but description exists! account={}".format(description_accountid))
                rest_client.delete("splunk_ta_aws_aws_description/{}".format("{}_audit".format(description_accountid)), owner='nobody',
                                   app='Splunk_TA_aws',
                                   output_mode='json')

    for org_account in org_accounts:
        role_name = helper.get_arg('aws_description_role_name')
        cred_arn = "arn:aws:iam::{}:role/{}".format(org_account['Id'], role_name)
        cred_name = "{}_audit".format(org_account['Id'])
        aws.configure_ta_cred(cred_name, cred_arn, ta_creds)
        helper.log_info("Checking if aws_account_id={} has role={} configured".format(org_account['Id'], role_name))


        # Setup description
        service_definition = aws.find_in_dict(description_definitions, 'name', cred_name)
        service_endpoint = 'splunk_ta_aws_aws_description'
        # s3_buckets/42300,
        # cloudfront_distributions/42300,

        service_config = {
            "name": cred_name,
            "account": "SplunkLoader-AWS",
            "aws_iam_role": cred_name,
            "regions": "ap-northeast-1,ap-northeast-2,ap-south-1,ap-southeast-1,ap-southeast-2,ca-central-1,eu-central-1,eu-west-1,eu-west-2,sa-east-1,us-east-1,us-east-2,us-west-1,us-west-2",
            "apis": "ec2_volumes/42300,ec2_instances/42300,ec2_reserved_instances/42300,ebs_snapshots/42300,classic_load_balancers/42300,application_load_balancers/42300,vpcs/42300,vpc_network_acls/42300,vpc_subnets/42300,rds_instances/42300,ec2_key_pairs/42300,ec2_security_groups/42300,ec2_images/42300,ec2_addresses/42300,lambda_functions/42300,iam_users/3600",
            "sourcetype": "aws:description",
            "index": helper.get_output_index()
        }
        aws.configure_service(service_config, service_endpoint, service_definition)

    input_type = helper.get_input_type()
    event = helper.new_event(source=input_type, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(),
                             data="Finished configuring IAM Roles and description")
    ew.write_event(event)

    helper.log_warning("END")
    exit(0)

