## AWS Compliance Repair
This demo PoC shows how to auto-remediate compliance issues at scale across accounts in your AWS account.

## Design

## Prerequisites
This assumes you already have Macie setup with multi account.

## Deployment
* Depoly the terraform main template into your central security account. This account should also be the same as your macie master account.
* Template includes
  * CloudWatch Orgnization Events Bus
  * ComplianceRepair Lambda Role
  * ComplianceRepair Lambda Function
  * CloudWatch events for
    * iam:UpdateAccountPasswordPolicy
    * cloudtrail:StopLogging
    * s3:DeleteBucketPublicAccessBlock, s3:PutBucketPublicAccessBlock, s3:CreateBucket
    * config:StopConfigurationRecorder

* Deploy the terraform spoke template into your spoke accounts.
* Template includes
  * CloudWatch Events Bus Role
  * ComplianceRepair Cross Account Role
  * CloudWatch events for
    * iam:UpdateAccountPasswordPolicy
    * cloudtrail:StopLogging
    * s3:DeleteBucketPublicAccessBlock, s3:PutBucketPublicAccessBlock, s3:CreateBucket
    * config:StopConfigurationRecorder

## License
This library is licensed under the Apache 2.0 License.