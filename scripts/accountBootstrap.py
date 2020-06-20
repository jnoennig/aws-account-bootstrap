"""
A Lambda function that is triggered by the Control Tower CloudWatch Event 'CreateManagedAccount'.
It automates configuration items that are not included in Control Tower.

The Amazon copyright covers the GuardDuty functions taken from:
https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts

Copyright 2018 Amazon.com, Inc. or its affiliates.
All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at
   http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file.
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script orchestrates the enablement and centralization of GuardDuty across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and region to enable GuardDuty.
It creates each account as a Member in the GuardDuty Master account.
It invites and accepts the invite for each Member account.

Copyright 2020 Jason Noennig
All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at "license" file accompanying this file.
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

MODIFIED by: Jason Noennig

Changelog:
2019-12-03: Modified GuardDuty functions to work with Lambda
2019-12-06: Added enabling AWS Config GuardDuty rule
2020-03-18: Added all non-GuardDuty functions and modified GuardDuty functions to work
    with Control Tower CloudWatch Event 'CreateManagedAccount'
"""

import os
import logging
import time
import json
from collections import OrderedDict
import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

def assume_role(aws_account_number, role_name, region='us-west-2'):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region

    Modified by Jason Noennig
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='AccountBootstrap'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name=region
    )

    LOGGER.info("Assumed session for {}.".format(
        aws_account_number
    ))

    return session

def get_enabled_regions(enabled_regions, aws_service):
    """
    Gets all supported regions for a specified AWS service
    If no regions are specified it returns all regions
    :param enabled_regions: User specified regions
    :param aws_service: AWS service you want to check
    :return: list of regions

    Modified by Jason Noennig
    """
    session = boto3.session.Session()

    region_results = []
    if enabled_regions:
        region_results = [str(item).lower().strip() for item in enabled_regions.split(',')]
        LOGGER.info("Enabling in these regions: {}".format(region_results))
    else:
        region_results = session.get_available_regions(aws_service)
        LOGGER.info("Enabling in all available regions {}".format(region_results))
    return region_results

def create_alias(session, member_account_name, member_account_id):
    '''
    Creates an alias for an account
    :param session: IAM session
    :param member_account_name: AWS target account name
    :param member_account_id: AWS target account id
    :return: API response
    '''
    try:
        # You can prepend or append a string to make the account_alias globally unique
        account_alias = member_account_name
        iam = session.client('iam')
        response = iam.create_account_alias(
            AccountAlias=account_alias
        )
        LOGGER.info('Set account {0} alias to: {1}'.format(member_account_id, account_alias))
        return response
    except ClientError as e:
        LOGGER.error('Failed setting alias for account {0}: {1}'.format(member_account_id, e))

def update_iam_pwd_policy(session, member_account_id):
    '''
    Updates the accounts IAM password policy
    :param session: IAM session
    :param member_account_id: AWS target account id
    :return: API response
    '''
    try:
        iam = session.client('iam')
        response = iam.update_account_password_policy(
            MinimumPasswordLength=15,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            MaxPasswordAge=365,
            PasswordReusePrevention=24,
            HardExpiry=True
        )
        LOGGER.info('Set account {0} password policy'.format(member_account_id))
        return response
    except ClientError as e:
        LOGGER.error('Failed to set account {0} IAM password policy: {1}'.format(member_account_id, e))

def enable_s3_pub_block(session, member_account_id):
    '''
    Enables S3 public access block
    :param session: IAM session
    :param member_account_id: AWS target account id
    :return: API response
    '''
    try:
        s3 = session.client('s3control')
        response = s3.put_public_access_block(
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            },
            AccountId=member_account_id
        )
        LOGGER.info('Set account {0} S3 public access block at account level'.format(member_account_id))
        return response
    except ClientError as e:
        LOGGER.error('Failed setting S3 public access block for account {0}: {1}'.format(member_account_id, e))

def logging_bucket(session, region, member_account_name, member_account_id):
    '''
    Creates the S3 access logging bucket and returns the responses
    :param session: IAM session
    :param region: AWS region to deploy bucket
    :param member_account_name: AWS target account name
    :param member_account_id: AWS target account id
    '''
    response_dict = {}
    # If bucket name needs to be more unique prepend or append string to bucket_name
    bucket_name = member_account_name + '-s3accesslogs-' + region
    s3 = session.client('s3')
    try:
        # Creating logging bucket
        LOGGER.info('Creating bucket {} in region {}'.format(bucket_name, region))
        if region == 'us-east-1':
            s3 = session.client('s3')
            create_response = s3.create_bucket(
                Bucket=bucket_name
            )
            acl_response = s3.put_bucket_acl(
                ACL='log-delivery-write',
                Bucket=bucket_name
            )
        else:
            create_response = s3.create_bucket(
                ACL='log-delivery-write',
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                }
            )
        response_dict.update({'createBucket': create_response})
    except ClientError as e:
        LOGGER.error('Failed creating S3 logging bucket for account {0}: {1}'.format(member_account_id, e))
    LOGGER.info('Created bucket {}'.format(bucket_name))
    # Encrypting logging bucket
    try:
        LOGGER.info('Setting encryption on bucket {}'.format(bucket_name))
        encrypt_response = s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules':[
                    {
                        'ApplyServerSideEncryptionByDefault':{
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        response_dict.update({'encryptBucket': encrypt_response})
    except ClientError as e:
        LOGGER.error('Failed creating S3 logging bucket for account {0}: {1}'.format(member_account_id, e))
    # Versioning logging bucket
    try:
        LOGGER.info('Enabling bucket versioning on bucket {}'.format(bucket_name))
        ver_response = s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                'Status':'Enabled'
            }
        )
        response_dict.update({'versionBucket': ver_response})
    except ClientError as e:
        LOGGER.error('Failed enabling versioning on S3 logging bucket for account {0}: {1}'.format(member_account_id, e))
    # Deny public access
    try:
        LOGGER.info('Denying public access on bucket {}'.format(bucket_name))
        public_response = s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        response_dict.update({'publicBucket': public_response})
    except ClientError as e:
        LOGGER.error('Failed denying public access on S3 logging bucket for account {0}: {1}'.format(member_account_id, e))
    # Bucket lifecycle configuration
    try:
        LOGGER.info('Enabling lifecycle configuration on bucket {}'.format(bucket_name))
        lifecycle_response = s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Expiration': {
                            'Days': 365
                        },
                        'ID': 'cleanup',
                        'Prefix': '',
                        'Status': 'Enabled',
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 90
                        },
                        'AbortIncompleteMultipartUpload': {
                            'DaysAfterInitiation': 7
                        }
                    }
                ]
            }
        )
        response_dict.update({'lifecycleBucket': lifecycle_response})
    except ClientError as e:
        LOGGER.error('Failed setting lifecycle configuration on S3 logging bucket for account {0}: {1}'.format(member_account_id, e))
    return response_dict

def cf_stacksets(stackset_name, member_account_id, region_list):
    '''
    Updates a StackSet with a new name.
    :param stackset_name: Name of the StackSet
    :param member_account_id: AWS target account id
    :param region_list: List of AWS regions
    :return: response
    '''
    try:
        cf = boto3.client('cloudformation')
        response = cf.create_stack_instances(
            StackSetName=stackset_name,
            Accounts=[member_account_id],
            Regions=region_list
        )
        LOGGER.info('Deployed stack in StackSet {0} for account {1}'.format(stackset_name, member_account_id))
        return response
    except ClientError as e:
        LOGGER.error('Error updating CloudFormation StackSet {0}: {1}'.format(stackset_name, e))

# Setup GuardDuty in master memeber relationship

def get_master_members(aws_region, detector_id):
    """
    Returns a list of current members of the GuardDuty master account
    :param aws_region: AWS Region of the GuardDuty master account
    :param detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """

    member_dict = dict()

    gd_client = boto3.client('guardduty', region_name=aws_region)

    # Need to paginate and iterate over results
    paginator = gd_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }

    page_iterator = paginator.paginate(**operation_parameters)

    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update({member['AccountId']: member['RelationshipStatus']})

    return member_dict

def get_member_emails(aws_region, detector_id):
    '''
    Returns a dictionary of account IDs and emails
    :param aws_region (us-west-2): defaults to us-west-2 as that is our default region
    :param detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: dict of AwsAccountId:email
    '''
    member_dict = dict()
    gd_client = boto3.client('guardduty', region_name=aws_region)
    # Need to paginate and iterate over results
    paginator = gd_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update({member['AccountId']: member['Email']})
    return member_dict

def list_detectors(client, aws_region):
    """
    Lists the detectors in a given Account/Region
    Used to detect if a detector exists already
    :param client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """

    detector_dict = client.list_detectors()

    if detector_dict['DetectorIds']:
        for detector in detector_dict['DetectorIds']:
            detector_dict.update({aws_region: detector})

    else:
        detector_dict.update({aws_region: ''})

    return detector_dict

def master_account_check(master_account, guardduty_regions):
    """
    Enables GuardDuty in the regions specified
    :param master_account: Master Account ID
    :param guardduty_regions: Regions to enable GuardDuty
    :returns: A tuple with failed regions and detector id dict
    """
    failed_master_regions = []
    master_detector_id_dict = dict()
    # Processing Master account
    for aws_region in guardduty_regions:
        try:
            aws_region = aws_region.lower().strip()
            gd_client = boto3.client('guardduty', region_name=aws_region)

            detector_dict = list_detectors(gd_client, aws_region)

            if detector_dict[aws_region]:
                # a detector exists
                LOGGER.info('Found existing detector {detector} in {region} for {account}'.format(
                    detector=detector_dict[aws_region],
                    region=aws_region,
                    account=master_account
                ))

                master_detector_id_dict.update({aws_region: detector_dict[aws_region]})

            else:

                # create a detector
                detector_str = gd_client.create_detector(Enable=True)['DetectorId']
                LOGGER.info('Created detector {detector} in {region} for {account}'.format(
                    detector=detector_str,
                    region=aws_region,
                    account=master_account
                ))

                master_detector_id_dict.update({aws_region: detector_str})
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                LOGGER.error("Failed to list detectors in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue").format(aws_region,aws_region)
                failed_master_regions.append(aws_region)
    return (failed_master_regions, master_detector_id_dict)

def add_config_rule(session, master_account, aws_region):
    """
    Adds guardduty-enabled-centralized AWS Config rule
    :param session: AWS session object
    :param master_account: GuardDuty master account
    :param aws_region: AWS region
    :returns: response of API call
    """
    config = session.client('config', region_name=aws_region)
    try:
        input_parameters = {'CentralMonitoringAccount': master_account}
        response = config.put_config_rule(
            ConfigRule={
                'ConfigRuleName': 'guardduty-enabled-centralized',
                'Description': 'Checks whether Amazon GuardDuty is enabled in your AWS account and region. If you provide an AWS account for centralization, the rule evaluates the GuardDuty results in that account. The rule is compliant when GuardDuty is enabled.',
                'Scope': {},
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'GUARDDUTY_ENABLED_CENTRALIZED',
                },
                'InputParameters': json.dumps(input_parameters),
                'MaximumExecutionFrequency': 'TwentyFour_Hours',
                'ConfigRuleState': 'ACTIVE'
            }
        )
        LOGGER.info('AWS Config GuardDuty rule enabled')
        return response
    except ClientError as e:
        LOGGER.error(e)

def invite_members(master_account, aws_account_dict, assume_role_name, guardduty_regions, master_detector_id_dict):
    """
    Invites member accounts to the GuardDuty master
    :param master_account: Master Account ID
    :param aws_account_dict: Dictionary of member Account IDs and email addresses
    :param assume_role_name: AWS IAM role to assume in the member accounts
    :param guardduty_regions: Regions to enable GuardDuty in
    :param master_detector_id_dict: Dictionary of Master Account GuardDuty dectotor IDs
    :returns: List of failed accounts
    """
    # Setting the invitationmessage
    gd_invite_message = 'Account {account} invites you to join GuardDuty.'.format(account=master_account)
    failed_accounts = []
    for account in aws_account_dict.keys():
        try:
            session = assume_role(account, assume_role_name)

            for aws_region in guardduty_regions:
                LOGGER.info('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))

                gd_client = session.client('guardduty', region_name=aws_region)

                # get detectors for this region
                detector_dict = list_detectors(gd_client, aws_region)
                detector_id = detector_dict[aws_region]

                # If detector does not exist, create it
                if detector_id:
                    # a detector exists
                    LOGGER.info('Found existing detector {detector} in {region} for {account}'.format(
                        detector=detector_id,
                        region=aws_region,
                        account=account
                    ))

                else:
                    # create a detector
                    detector_str = gd_client.create_detector(Enable=True)['DetectorId']
                    LOGGER.info('Created detector {detector} in {region} for {account}'.format(
                        detector=detector_str,
                        region=aws_region,
                        account=account
                    ))

                    detector_id = detector_str

                master_detector_id = master_detector_id_dict[aws_region]
                member_dict = get_master_members(aws_region, master_detector_id)

                # If detector is not a member of the GuardDuty master account, add it
                if account not in member_dict:
                    gd_client = boto3.client('guardduty', region_name=aws_region)

                    gd_client.create_members(
                        AccountDetails=[
                            {
                                'AccountId': account,
                                'Email': aws_account_dict[account]
                            }
                        ],
                        DetectorId=master_detector_id
                    )

                    LOGGER.info('Added Account {monitored} to member list in GuardDuty master account {master} for region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                    start_time = int(time.time())
                    while account not in member_dict:
                        if (int(time.time()) - start_time) > 180:
                            LOGGER.warning("Membership did not show up for account {}, skipping".format(account))
                            break

                        time.sleep(5)
                        member_dict = get_master_members(aws_region, master_detector_id)

                else:

                    LOGGER.info('Account {monitored} is already a member of {master} in region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                # Check if Verification Was failed before, delete and add it again.
                if member_dict[account] == 'EmailVerificationFailed':
                    # Member is enabled and already being monitored
                    LOGGER.error('Account {account} Error: EmailVerificationFailed'.format(account=account))
                    gd_client = boto3.client('guardduty', region_name=aws_region)
                    gd_client.disassociate_members(
                        AccountIds=[
                            account
                        ],
                        DetectorId=master_detector_id
                    )

                    gd_client.delete_members(
                        AccountIds=[
                            account
                        ],
                        DetectorId=master_detector_id
                    )

                    LOGGER.warning('Deleting members for {account} in {region}'.format(
                        account=account,
                        region=aws_region
                    ))

                    gd_client.create_members(
                        AccountDetails=[
                            {
                                'AccountId': account,
                                'Email': aws_account_dict[account]
                            }
                        ],
                        DetectorId=master_detector_id
                    )

                    LOGGER.info('Added Account {monitored} to member list in GuardDuty master account {master} for region {region}'.format(
                        monitored=account,
                        master=master_account,
                        region=aws_region
                    ))

                    start_time = int(time.time())
                    while account not in member_dict:
                        if (int(time.time()) - start_time) > 300:
                            LOGGER.warning("Membership did not show up for account {}, skipping".format(account))
                            break

                        time.sleep(5)
                        member_dict = get_master_members(aws_region, master_detector_id)


                if member_dict[account] == 'Enabled':
                    # Member is enabled and already being monitored
                    LOGGER.info('Account {account} is already enabled'.format(account=account))

                else:
                    master_gd_client = boto3.client('guardduty', region_name=aws_region)
                    gd_client = session.client('guardduty', region_name=aws_region)

                    if member_dict[account] == 'Disabled' :
                        # Member was disabled
                        LOGGER.error('Account {account} Error: Disabled'.format(account=account))
                        master_gd_client.start_monitoring_members(
                            AccountIds=[
                                account
                            ],
                            DetectorId=master_detector_id
                        )
                        LOGGER.info('Account {account} Re-Enabled'.format(account=account))

                    while member_dict[account] != 'Enabled':

                        if member_dict[account] == 'Created' :
                            # Member has been created in the GuardDuty master account but not invited yet
                            master_gd_client = boto3.client('guardduty', region_name=aws_region)

                            master_gd_client.invite_members(
                                AccountIds=[
                                    account
                                ],
                                DetectorId=master_detector_id,
                                Message=gd_invite_message
                            )

                            LOGGER.info('Invited Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                monitored=account,
                                master=master_account,
                                region=aws_region
                            ))

                        if member_dict[account] == 'Invited' or member_dict[account] == 'Resigned':
                            # member has been invited so accept the invite

                            response = gd_client.list_invitations()

                            invitation_dict = dict()

                            invitation_id = None
                            for invitation in response['Invitations']:
                                invitation_id = invitation['InvitationId']

                            if invitation_id is not None:
                                gd_client.accept_invitation(
                                    DetectorId=detector_id,
                                    InvitationId=invitation_id,
                                    MasterId=str(master_account)
                                )
                                LOGGER.info('Accepting Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                    monitored=account,
                                    master=master_account,
                                    region=aws_region
                                ))

                        # Refresh the member dictionary
                        member_dict = get_master_members(aws_region, master_detector_id)

                    LOGGER.info('Finished {account} in {region}'.format(account=account, region=aws_region))
                add_config_rule(session, master_account, aws_region)
        except ClientError as e:
            LOGGER.error("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })
    return failed_accounts

def lambda_handler(event, context):
    '''
    Main function
    '''
    member_account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountId']
    member_account_name = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountName']
    master_account = boto3.client('sts').get_caller_identity().get('Account')
    email_base = os.environ['emailBase']
    email_domain = os.environ['emailDomain']
    assume_role_name = os.environ['assumeRoleName']
    enabled_regions = os.environ['enabledRegions']
    stackset_names = os.environ['stackSetNames']
    session = assume_role(member_account_id, assume_role_name)
    # Create resources
    # Alias
    create_alias(session, member_account_name, member_account_id)
    # IAM password policy
    update_iam_pwd_policy(session, member_account_id)
    # Enable S3 publick block
    enable_s3_pub_block(session, member_account_id)
    # S3 logging buckets
    s3_regions = get_enabled_regions(enabled_regions, 's3')
    for region in s3_regions:
        session = assume_role(member_account_id, assume_role_name, region=region)
        logging_bucket(session, region, member_account_name, member_account_id)
    # CloudFormation
    cf_regions = get_enabled_regions(enabled_regions, 'cloudformation')
    stackset_names = [str(item).strip() for item in stackset_names.split(',')]
    for stackset_name in stackset_names:
        if stackset_name:
            cf_stacksets(stackset_name, member_account_id, cf_regions)
        else:
            LOGGER.info('CloudFormation StackSet list empty')
    # GuardDuty
    # Change default_gd_region to your main region
    default_gd_region = 'us-west-2'
    aws_account_dict = OrderedDict()
    gd_regions = get_enabled_regions(enabled_regions, 'guardduty')
    gd_client = boto3.client('guardduty', region_name=default_gd_region)
    detector_dict = list_detectors(gd_client, default_gd_region)
    detector_id = detector_dict[default_gd_region]
    members = get_member_emails(default_gd_region, detector_id)
    member_email = email_base + '+' + member_account_name + '@' + email_domain
    aws_account_dict.update({member_account_id: member_email})
    if len(members) > 1000:
        raise Exception("Only 1000 accounts can be linked to a single master account")
    master_account_checked = master_account_check(master_account, gd_regions)
    master_detector_id_dict = master_account_checked[1]
    failed_master_regions = master_account_checked[0]
    for failed_region in failed_master_regions:
        gd_regions.remove(failed_region)
    # Processing accounts to be linked
    failed_accounts = invite_members(
        master_account,
        aws_account_dict,
        assume_role_name,
        gd_regions,
        master_detector_id_dict
    )
    if len(failed_accounts) > 0:
        for account in failed_accounts:
            LOGGER.error("GuardDuty failed to enable accounts")
            LOGGER.error("{}: \n\t{}".format(
                list(account.keys())[0],
                account[list(account.keys())[0]]
                )
            )
