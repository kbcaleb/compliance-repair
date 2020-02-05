provider "aws" {
    profile = "master"
    region = "us-east-1" // Replace with global trail region
}

# Lambda Role
resource "aws_iam_role" "ComplianceRepairLambdaRole" {
    name = "ComplianceRepairLambdaRole"
    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": ["sts:AssumeRole"],
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": "ComplianceRepairLambdaRole"
        }
    ]
}
EOF
}

# Lambda Basic Execution Role
resource "aws_iam_role_policy_attachment" "AttachAWSLambdaBasicExecutionRole" {
    role = aws_iam_role.ComplianceRepairLambdaRole.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda Role Policy Data
data "aws_iam_policy_document" "ComplianceRepairLambdaPolicy" {
    statement {
        sid = "ComplianceRepairLambdaCloudTrailPolicy"
        actions = [
            "cloudtrail:StartLogging"
        ]
        resources = ["*"]
    }
    statement {
        sid = "ComplianceRepairLambdaPasswordPolicy"
        actions = [
            "iam:GetAccountPasswordPolicy",
            "iam:UpdateAccountPasswordPolicy"
        ]
        resources = ["*"]
    }
    statement {
        sid = "ComplianceRepairLambdaS3PublicPolicy"
        actions = [
            "s3:PutAccountPublicAccessBlock",
            "s3:GetAccountPublicAccessBlock"
        ]
        resources = ["*"]
    }
}

# Lambda Role Policy
resource "aws_iam_policy" "ComplianceRepairLambdaPolicy" {
    name = "ComplianceRepairLambdaPolicy"
    path = "/"
    policy = data.aws_iam_policy_document.ComplianceRepairLambdaPolicy.json
}

# Lambda Role Policy Attachment
resource "aws_iam_role_policy_attachment" "AttachComplianceRepairLambdaPolicy" {
    role = aws_iam_role.ComplianceRepairLambdaRole.name
    policy_arn = aws_iam_policy.ComplianceRepairLambdaPolicy.arn
}

# Lambda Function
resource "aws_lambda_function" "ComplianceRepair" {
    filename = "function.zip"
    function_name = "ComplianceRepair"
    role = aws_iam_role.ComplianceRepairLambdaRole.arn
    handler = "lambda_function.lambda_handler"
    source_code_hash = filebase64sha256("function.zip")
    runtime = "python3.8"
}

# CloudWatch PasswordPolicyChange Event
resource "aws_cloudwatch_event_rule" "PasswordPolicyChange" {
    name        = "PasswordPolicyChange"
    description = "Password policy change"

    event_pattern = <<PATTERN
    {
        "source": [
            "aws.iam"
        ],
        "detail-type": [
            "AWS API Call via CloudTrail"
        ],
        "detail": {
            "eventSource": [
                "iam.amazonaws.com"
            ],
            "eventName": [
                "UpdateAccountPasswordPolicy"
            ]
        }
    }
    PATTERN
}

# CloudWatch CloudtrailLoggingDisabled Event
resource "aws_cloudwatch_event_rule" "CloudtrailLoggingDisabled" {
    name        = "CloudtrailLoggingDisabled"
    description = "CloudTrail logging disabled"

    event_pattern = <<PATTERN
    {
        "source": [
            "aws.cloudtrail"
        ],
        "detail-type": [
            "AWS API Call via CloudTrail"
        ],
        "detail": {
            "eventSource": [
                "cloudtrail.amazonaws.com"
            ],
            "eventName": [
                "StopLogging"
            ]
        }
    }
    PATTERN
}

# S3 Account Public Event
resource "aws_cloudwatch_event_rule" "S3AccountPublicPolicyChange" {
    name        = "S3AccountPublicPolicyChange"
    description = "S3 Account Public Policy Change"

    event_pattern = <<PATTERN
    {
        "source": [
            "aws.s3"
        ],
        "detail-type": [
            "AWS API Call via CloudTrail"
        ],
        "detail": {
            "eventSource": [
                "s3.amazonaws.com"
            ],
            "eventName": [
                "PutAccountPublicAccessBlock",
                "DeleteAccountPublicAccessBlock",
                "DeleteBucketPublicAccessBlock",
                "PutBucketPublicAccessBlock"
            ]
        }
    }
    PATTERN
}

# Lambda PasswordPolicyChange Permission
resource "aws_lambda_permission" "AllowExecutionFromPasswordPolicyChange" {
    statement_id = "AllowExecutionFromPasswordPolicyChange"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.PasswordPolicyChange.arn
}

# Lambda CloudtrailLoggingDisabled Permission
resource "aws_lambda_permission" "AllowExecutionFromCloudtrailLoggingDisabled" {
    statement_id = "AllowExecutionFromCloudtrailLoggingDisabled"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.CloudtrailLoggingDisabled.arn
}

# Lambda CloudtrailLoggingDisabled Permission
resource "aws_lambda_permission" "AllowExecutionFromS3AccountPublicPolicyChange" {
    statement_id = "AllowExecutionFromS3AccountPublicPolicyChange"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.S3AccountPublicPolicyChange.arn
}

# CloudWatch PasswordPolicyChange Event Target
resource "aws_cloudwatch_event_target" "LambdaPasswordPolicy" {
    rule        = aws_cloudwatch_event_rule.PasswordPolicyChange.name
    target_id   = "SendToLambda"
    arn         = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch CloudtrailLoggingDisabled Event Target
resource "aws_cloudwatch_event_target" "LambdaCloudtrailLogging" {
    rule        = aws_cloudwatch_event_rule.CloudtrailLoggingDisabled.name
    target_id   = "SendToLambda"
    arn         = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch S3AccountPublicPolicyChange Event Target
resource "aws_cloudwatch_event_target" "LambdaS3AccountPublicPolicyChange" {
    rule        = aws_cloudwatch_event_rule.S3AccountPublicPolicyChange.name
    target_id   = "SendToLambda"
    arn         = aws_lambda_function.ComplianceRepair.arn
}