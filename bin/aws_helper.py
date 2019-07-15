import boto3
from botocore.exceptions import EndpointConnectionError
from botocore.exceptions import ClientError
import logging as logger
import os
import json
import splunk.entity as entity

logger.basicConfig(level=logger.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    filename=os.path.join(os.environ['SPLUNK_HOME'],'var','log','splunk','TA-aws-configurator-aws_helper.log'),
    filemode='a')


class aws_helper:

    def __init__(self, splunk_helper, rest_client):
        self.splunk_helper = splunk_helper
        self.rest_client = rest_client

    def aws_session(self, session=None, role_arn=None, session_name='splunk_session'):
        """
        If role_arn is given assumes a role and returns boto3 session
        otherwise return a regular session with the current IAM user/role
        """
        if role_arn:
            if session == None:
                client = boto3.client('sts')
            else:
                client = session.client('sts')
            response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            creds = response.get("Credentials", None)
            if creds is not None:
                session = boto3.Session(
                    aws_access_key_id=creds['AccessKeyId'],
                    aws_secret_access_key=creds['SecretAccessKey'],
                    aws_session_token=creds['SessionToken'])
            return session
        else:
            return boto3.Session()

    def get_orgs(self, session):
        client = session.client('organizations')
        org_accounts = []
        ou_paginator = client.get_paginator('list_organizational_units_for_parent')
        for org_unit in ou_paginator.paginate(ParentId="r-cvip"):
            for ou in org_unit["OrganizationalUnits"]:
                acct_paginator = client.get_paginator('list_accounts_for_parent')
                accounts = acct_paginator.paginate(ParentId=ou["Id"])
                for account_page in accounts:
                    for account in account_page["Accounts"]:
                        if account['Status']!="SUSPENDED":
                            org_accounts.append(account)
        return org_accounts

    def find_in_dict(self, dict_obj, key, value):
        self.splunk_helper.log_debug("Looking for {}={} in dict".format(key, value))
        for item in dict_obj:
            self.splunk_helper.log_debug("Looking at {}={}".format(key, item[key]))
            if item[key] == value:
                return item


    def get_app_credentials(self, session_key, owner, namespace):
        """
        :param session_key:
        :return: AWS Keys
        """
        import os, sys, logging as logger
        logger.basicConfig(level=logger.INFO,
                           format='%(asctime)s %(levelname)s %(message)s',
                           filename=os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk',
                                                 'ta_aws_surface_aws_surface_cloudtrail.log'),
                           filemode='a')

        try:
            # list all credentials
            entities = entity.getEntities(['admin', 'passwords'], namespace=namespace, owner='-', sessionKey=session_key,
                                          count=0)
        except Exception as unknown_exception:
            raise Exception("Could not get %s credentials from splunk. Error: %s"
                            % ("AWS_Trusted_Advisor", str(unknown_exception)))
        # grab first set of credentials
        if entities:
            for i, stanza in entities.items():
                if stanza['eai:acl']['app'] == namespace:
                    # cred = stanza['clear_password']
                    yield stanza
        else:
            message = 'No credentials have been found. Please set them up in your AWS console.'
            logger.warning(message, session_key, 'common.py')
            sys.exit(0)

    def get_incremental_sqs_definitions(self):
        response = self.rest_client.get(
            'splunk_ta_aws_aws_sqs_based_s3', owner='nobody', app='Splunk_TA_aws',
            output_mode='json', count=-1)
        if response.status not in (200, 201):
            self.splunk_helper.log_error("Failed to query", endpoint='splunk_ta_aws_aws_sqs_based_s3', reason=response.reason)
            raise Exception("Failed to query endpoint {}".format(response))
        return json.loads(response.body.read())['entry']


    def configure_service(self, service_config, service_endpoint, service_definition):
        create_service_def = False

        if service_definition:
            service_definition['content']['name'] = service_definition['name']
            for key in service_config:
                # ukey = unicode(key)
                if service_definition['content'][key] != service_config[key]:
                    self.splunk_helper.log_info(
                        "input definition key={} for name={} is different from expected, recreating.".format(key, service_config['name']))
                    create_service_def = True

        else:
            create_service_def = True

        if service_definition and create_service_def:

            self.splunk_helper.log_info("Recreating config")
            try:
                self.rest_client.delete("{}/{}".format(service_endpoint,service_config['name']), owner='nobody',
                                   app='Splunk_TA_aws',
                                   output_mode='json')
                self.splunk_helper.log_info("Deleted existing config for account={}".format(service_config['name']))
            except Exception as e:
                self.splunk_helper.log_info(e)

        if create_service_def:
            try:
                self.splunk_helper.log_info("Creating service configuration")
                self.rest_client.post('{}'.format(service_endpoint), owner='nobody', app='Splunk_TA_aws',
                                 body=service_config, output_mode='json')

            except Exception as e:
                self.splunk_helper.log_warning("Failed to add input for account={}".format(service_config['name']))
                self.splunk_helper.log_warning(e)

    def configure_ta_cred(self, cred_name, cred_arn, ta_creds):
        cred = self.find_in_dict(ta_creds, 'username', cred_name)

        if not cred:
            self.splunk_helper.log_info("Credential NOT found for username={}".format(cred_name))
            cred = {
                "name": cred_name,
                "arn": cred_arn
            }
            try:
                self.rest_client.post('splunk_ta_aws_iam_roles', owner='nobody', app='Splunk_TA_aws', body=cred,
                                 output_mode='json')
            except Exception as e:
                self.splunk_helper.log_info("Failed to add username={}".format(cred_name))
                self.splunk_helper.log_warning(e)
        else:
            self.splunk_helper.log_info("Credential was found for username={}".format(cred_name))
            # Does the ARN match the expected?
            cred_obj = json.loads(cred['clear_password'])
            if cred_arn != cred_obj['arn']:
                self.splunk_helper.log_warning("Credential does not match and needs updating...! username={}".format(cloudtrail_username))
