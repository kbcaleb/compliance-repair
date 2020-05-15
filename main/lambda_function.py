import os
import logging
import json
import boto3
import botocore.session
from botocore.exceptions import ClientError
session = botocore.session.get_session()

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

def main(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN):
    eventname = event['detail']['eventName']
    if eventname == "UpdateAccountPasswordPolicy":
        repair_password_policy(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)
    if eventname == 'StopLogging':
        repair_cloudtrail_logging(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)
    if eventname == 'PutBucketPublicAccessBlock' or eventname == 'DeleteBucketPublicAccessBlock':
        repair_s3_public(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)
    if eventname == 'CreateBucket':
        add_new_bucket_to_macie(event)
    if eventname == "StopConfigurationRecorder":
        repair_config_recorder(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)

def repair_password_policy(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN):
    try:
        client = boto3.client(
            'iam',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        )
        response = client.get_account_password_policy()
        logger.debug("Password policy is--- %s" %response)

        if 'MinimumPasswordLength' in response['PasswordPolicy']:
            minimumpasswordlength = response['PasswordPolicy']['MinimumPasswordLength']
        else:
            minimumpasswordlength = ''
        
        if 'RequireSymbols' in response['PasswordPolicy']:
            requiresymbols = response['PasswordPolicy']['RequireSymbols']
        else:
            requiresymbols = ''
            
        if 'RequireNumbers' in response['PasswordPolicy']:
            requirenumbers = response['PasswordPolicy']['RequireNumbers']
        else:
            requirenumbers = ''
            
        if 'RequireUppercaseCharacters' in response['PasswordPolicy']:
            requireuppercasecharacters = response['PasswordPolicy']['RequireUppercaseCharacters']
        else:
            requireuppercasecharacters = ''
            
        if 'RequireLowercaseCharacters' in response['PasswordPolicy']:
            requirelowercasecharacters = response['PasswordPolicy']['RequireLowercaseCharacters']
        else:
            requirelowercasecharacters = ''
        
        if 'AllowUsersToChangePassword' in response['PasswordPolicy']:
            allowuserstochangepassword = response['PasswordPolicy']['AllowUsersToChangePassword']
        else:
            allowuserstochangepassword = ''
        
        if 'ExpirePasswords' in response['PasswordPolicy']:
            expirepasswords = response['PasswordPolicy']['ExpirePasswords']
        else:
            expirepasswords = ''
        
        if 'MaxPasswordAge' in response['PasswordPolicy']:
            maxpasswordage = response['PasswordPolicy']['MaxPasswordAge']
        else:
            maxpasswordage = ''
        
        if 'PasswordReusePrevention' in response['PasswordPolicy']:
            passwordreuseprevention = response['PasswordPolicy']['PasswordReusePrevention']
        else:
            passwordreuseprevention = ''
            
        if 'HardExpiry' in response['PasswordPolicy']:
            hardexpiry = response['PasswordPolicy']['HardExpiry']
        else:
            hardexpiry = ''
        
        if minimumpasswordlength != 14 or requiresymbols != True or requirenumbers != True or requireuppercasecharacters != True or requirelowercasecharacters != True or allowuserstochangepassword != True or expirepasswords != True or maxpasswordage != 90 or passwordreuseprevention != 24 or hardexpiry != False:
            logger.info("Account password policy changed to non complaint setting-- %s. Enabling the complaint password policy again....." %response)
            try:
                updatepasswordpolicy = client.update_account_password_policy(
                    MinimumPasswordLength=14,
                    RequireSymbols=True,
                    RequireNumbers=True,
                    RequireUppercaseCharacters=True,
                    RequireLowercaseCharacters=True,
                    AllowUsersToChangePassword=True,
                    MaxPasswordAge=90,
                    PasswordReusePrevention=24,
                    HardExpiry=False
                )
                logger.debug("Response on setting new password policy- %s" %updatepasswordpolicy)
            except ClientError as e:
                logger.error("An error occurred: %s" %e)

    except ClientError as e:
        logger.error("An error occurred: %s" %e)

def repair_cloudtrail_logging(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN):
    # CloudTrail logging
    cloudtrailArn = event['detail']['requestParameters']['name']
    logger.debug("CloudTrail Arn is--- %s" %cloudtrailArn)
    logger.info("AWS CloudTrail logging disabled for AWS Cloudtrail with ARN-- %s. Enabling the AWS Cloudtrail back again....." %cloudtrailArn)
    try:
        client = boto3.client(
            'cloudtrail',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        )
        enablelogging = client.start_logging(Name=cloudtrailArn)
        logger.debug("Response on enable CloudTrail logging- %s" %enablelogging)
        
    except ClientError as e:
        logger.error("An error occurred: %s" %e) 

def repair_s3_public(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN):
    s3bucket = event['detail']['requestParameters']['bucketName']
    logger.debug("S3 bucket is--- %s" %s3bucket)
    try:
        client = boto3.client(
            's3',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        )
        response = client.get_public_access_block(
            Bucket = s3bucket
        )
        logger.debug("S3 public access policy is--- %s" %response)

        if 'BlockPublicAcls' in response['PublicAccessBlockConfiguration']:
            blockpublicacls = response['PublicAccessBlockConfiguration']['BlockPublicAcls']
        else:
            blockpublicacls = ''

        if 'IgnorePublicAcls' in response['PublicAccessBlockConfiguration']:
            ignorepublicacls = response['PublicAccessBlockConfiguration']['IgnorePublicAcls']
        else:
            ignorepublicacls = ''

        if 'BlockPublicPolicy' in response['PublicAccessBlockConfiguration']:
            blockpublicpolicy = response['PublicAccessBlockConfiguration']['BlockPublicPolicy']
        else:
            blockpublicpolicy = ''

        if 'RestrictPublicBuckets' in response['PublicAccessBlockConfiguration']:
            restrictpublicbuckets = response['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
        else:
            restrictpublicbuckets = ''

        if blockpublicacls != True or ignorepublicacls != True or blockpublicpolicy != True or restrictpublicbuckets != True:
            logger.info("S3 public access was modified for S3 bucket-- %s. Enabling the S3 public access block again....." %response)
            try:
                updates3bucketpublicpolicy = client.put_public_access_block(
                    Bucket = s3bucket,
                    PublicAccessBlockConfiguration = {
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                logger.debug("Response on setting new s3 bucket public policy- %s" %updates3bucketpublicpolicy)
            except ClientError as e:
                logger.error("An error occurred: %s" %e)

    except ClientError as e:
        logger.error("An error occurred: %s" %e)

def add_new_bucket_to_macie(event):
    account_id = event['account']
    s3bucket = event['detail']['requestParameters']['bucketName']
    logger.debug("S3 bucket is--- %s" %s3bucket)
    try:
        client = boto3.client('macie')
        newbucketenablemacie = client.associate_s3_resources(
            memberAccountId = account_id,
            s3Resources=[
                {
                    'bucketName': s3bucket,
                    'classificationType': {
                        'oneTime': 'FULL',
                        'continuous': 'FULL'
                    }
                },
            ]
        )
        logger.debug("Response on setting new s3 bucket Macie policy- %s" %newbucketenablemacie)
    except ClientError as e:
        logger.error("An error occurred: %s" %e)

def repair_config_recorder(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN):
    configrecordername = event['detail']['requestParameters']['configurationRecorderName']
    logger.debug("Config recorder name is--- %s" %configrecordername)
    logger.info("AWS Config recorder disabled for-- %s. Enabling the AWS Config recorder again....." %configrecordername)
    
    try:
        client = boto3.client(
            'config',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        )
        enableconfigrecorder = client.start_configuration_recorder(ConfigurationRecorderName=configrecordername)
        logger.debug("Response on enable CloudTrail logging- %s" %enableconfigrecorder)
        
    except ClientError as e:
        logger.error("An error occurred: %s" %e)

def lambda_handler(event, context):
    logger.setLevel(logging.DEBUG)
    logger.debug("Event is-- %s" %event)
    account_id = event['account']
    client = boto3.client('sts')
    exec_account_id = client.get_caller_identity()["Account"]

    if exec_account_id == account_id:
        logger.info("Performing local compliance repair on- %s ", account_id)
        ACCESS_KEY = os.environ['AWS_ACCESS_KEY_ID']
        SECRET_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
        SESSION_TOKEN = os.environ['AWS_SESSION_TOKEN']
        main(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)
    else:
        logger.info("Performing remote compliance repair on- %s ", account_id)
        cross_account_role_name = os.environ['CROSSROLE']
        cross_account_role = "arn:aws:iam::" + account_id + ":role/" + cross_account_role_name
        logger.info("Using assumed role-- %s for compliance repair" %cross_account_role)
        sts_connection = boto3.client('sts')
        assume_acct = sts_connection.assume_role(
            RoleArn=cross_account_role,
            RoleSessionName="ComplianceRepairCrossAccount"
        )

        ACCESS_KEY = assume_acct['Credentials']['AccessKeyId']
        SECRET_KEY = assume_acct['Credentials']['SecretAccessKey']
        SESSION_TOKEN = assume_acct['Credentials']['SessionToken']

        main(event, ACCESS_KEY, SECRET_KEY, SESSION_TOKEN)
