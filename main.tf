provider "aws" {
    profile = "svb-master"
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
            "s3:GetBucketPublicAccessBlock",
            "s3:PutBucketPublicAccessBlock"
        ]
        resources = ["*"]
    }
    statement {
        sid = "S3NewBucketMaciePolicy"
        actions = [
            "macie:AssociateS3Resources"
        ]
        resources = ["*"]
    }
    statement {
        sid = "ConfigRecorderLoggingPolicy"
        actions = [
            "config:StartConfigurationRecorder"
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

# CloudWatch S3PublicAccessChange Event
resource "aws_cloudwatch_event_rule" "S3PublicAccessChange" {
    name        = "S3PublicAccessChange"
    description = "S3 Public Access Change"

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
                "DeleteBucketPublicAccessBlock",
                "PutBucketPublicAccessBlock"
            ]
        }
    }
    PATTERN
}

# CloudWatch S3NewBucket Event
resource "aws_cloudwatch_event_rule" "S3NewBucket" {
    name        = "S3NewBucket"
    description = "S3 New Bucket"

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
                "CreateBucket"
            ]
        }
    }
    PATTERN
}

# CloudWatch ConfigRecorderStopped Event
resource "aws_cloudwatch_event_rule" "ConfigRecorderStopped" {
    name        = "ConfigRecorderStopped"
    description = "Config Recorder Stopped"

    event_pattern = <<PATTERN
    {
        "source": [
            "aws.config"
        ],
        "detail-type": [
            "AWS API Call via CloudTrail"
        ],
        "detail": {
            "eventSource": [
                "config.amazonaws.com"
            ],
            "eventName": [
                "StopConfigurationRecorder"
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

# Lambda S3PublicAccessChange Permission
resource "aws_lambda_permission" "AllowExecutionFromS3PublicAccessChange" {
    statement_id = "AllowExecutionFromS3PublicAccessChange"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.S3PublicAccessChange.arn
}

# Lambda S3NewBucket Permission
resource "aws_lambda_permission" "AllowExecutionFromS3NewBucket" {
    statement_id = "AllowExecutionFromS3NewBucket"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.S3NewBucket.arn
}

# Lambda ConfigRecorderStopped Permission
resource "aws_lambda_permission" "AllowExecutionFromConfigRecorderStopped" {
    statement_id = "AllowExecutionFromConfigRecorderStopped"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ComplianceRepair.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.ConfigRecorderStopped.arn
}

# CloudWatch PasswordPolicyChange Event Target
resource "aws_cloudwatch_event_target" "LambdaPasswordPolicy" {
    rule = aws_cloudwatch_event_rule.PasswordPolicyChange.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch CloudtrailLoggingDisabled Event Target
resource "aws_cloudwatch_event_target" "LambdaCloudtrailLogging" {
    rule = aws_cloudwatch_event_rule.CloudtrailLoggingDisabled.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch S3PublicAccessChange Event Target
resource "aws_cloudwatch_event_target" "LambdaS3PublicAccess" {
    rule = aws_cloudwatch_event_rule.S3PublicAccessChange.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch S3NewBucket Event Target
resource "aws_cloudwatch_event_target" "LambdaS3NewBucket" {
    rule = aws_cloudwatch_event_rule.S3NewBucket.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.ComplianceRepair.arn
}

# CloudWatch ConfigRecorderStopped Event Target
resource "aws_cloudwatch_event_target" "LambdaConfigRecorderStopped" {
    rule = aws_cloudwatch_event_rule.ConfigRecorderStopped.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.ComplianceRepair.arn
}
