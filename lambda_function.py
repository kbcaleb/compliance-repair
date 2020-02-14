import os
import logging
import json
import boto3
import botocore.session
from botocore.exceptions import ClientError
session = botocore.session.get_session()

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

def lambda_handler(event, context):
    logger.setLevel(logging.DEBUG)
    eventname = event['detail']['eventName']
    logger.debug("Event is-- %s" %event)
    logger.debug("Event Name is--- %s" %eventname)
    
    # CloudTrail logging
    if eventname == 'StopLogging':
        cloudtrailArn = event['detail']['requestParameters']['name']
        logger.debug("CloudTrail Arn is--- %s" %cloudtrailArn)
        logger.info("AWS CloudTrail logging disabled for AWS Cloudtrail with ARN-- %s. Enabling the AWS Cloudtrail back again....." %cloudtrailArn)
        
        try:
            client = boto3.client('cloudtrail')
            enablelogging = client.start_logging(Name=cloudtrailArn)
            logger.debug("Response on enable CloudTrail logging- %s" %enablelogging)
            
        except ClientError as e:
            logger.error("An error occurred: %s" %e)

    # Account Password Policy
    if eventname == 'UpdateAccountPasswordPolicy':

        try:
            client = boto3.client('iam')
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
                requireuppercasecharacters
                
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

    # S3 Public Access Changed
    if eventname == 'PutBucketPublicAccessBlock' or eventname == 'DeleteBucketPublicAccessBlock':
        s3bucket = event['detail']['requestParameters']['bucketName']
        logger.debug("S3 bucket is--- %s" %s3bucket)
        try:
            client = boto3.client('s3')
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

    # S3 add new buckets to Macie
    if eventname == 'CreateBucket':
        # Find true accountID when possible
        if 'recipientAccountId' in event['detail']:
            accountid = event['detail']['recipientAccountId']
        else:
            accountid = event['account']

        s3bucket = event['detail']['requestParameters']['bucketName']
        logger.debug("S3 bucket is--- %s" %s3bucket)
        try:
            client = boto3.client('macie')
            newbucketenablemacie = client.associate_s3_resources(
                memberAccountId = accountid,
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

    # Config recorder
    if eventname == 'StopConfigurationRecorder':
        configrecordername = event['detail']['requestParameters']['configurationRecorderName']
        logger.debug("Config recorder name is--- %s" %configrecordername)
        logger.info("AWS Config recorder disabled for-- %s. Enabling the AWS Config recorder again....." %configrecordername)
        
        try:
            client = boto3.client('config')
            enableconfigrecorder = client.start_configuration_recorder(ConfigurationRecorderName=configrecordername)
            logger.debug("Response on enable CloudTrail logging- %s" %enableconfigrecorder)
            
        except ClientError as e:
            logger.error("An error occurred: %s" %e)
