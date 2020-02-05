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

    if eventname == 'UpdateAccountPasswordPolicy':

        try:
            client = boto3.client('iam')
            response = client.get_account_password_policy()
            logger.debug("Password policy is -%s" %response)

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
            
            if minimumpasswordlength != 14 or requiresymbols != True or requirenumbers != True or requireuppercasecharacters != True or requirelowercasecharacters != True or allowuserstochangepassword != True or expirepasswords != True or maxpasswordage != 90 or passwordreuseprevention != 24:
                logger.info("Account password policy changed to non complaint setting-- %s. Enabling the complaint password policy again....." %response)
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

    if eventname == 'PutAccountPublicAccessBlock':
        try:
            client = boto3.client('s3control')
            accountid = event['detail']['accountId']
            response = client.get_public_access_block(
                AccountId = accountid
            )
            logger.debug("S3 public policy is -%s" %response)

            if 'BlockPublicAcls' in response['PublicAccessBlockConfiguration']:
                blockpublicacls = response['PublicAccessBlockConfiguration']['BlockPublicAcls']
            else:
                blockpublicacls = ''

            if 'IgnorePublicAcls' in response['PublicAccessBlockConfiguration']:
                ignorepublicacls = response['PublicAccessBlockConfiguration']['BlocIgnorePublicAclskPublicAcls']
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

            if BlockPublicAcls != True or IgnorePublicAcls != True or BlockPublicPolicy != True or RestrictPublicBuckets != True:
                logger.info("Account S3 public policy changed to non complaint setting-- %s. Enabling the complaint S3 public policy again....." %response)
                blocks3public = client.put_public_access_block(
                    PublicAccessBlockConfiguration = {
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    },
                    AccountId = accountid
                )
                logger.debug("Response on setting new S3 public policy- %s" %blocks3public)           

        except ClientError as e:
            logger.error("An error occurred: %s" %e)
