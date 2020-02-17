provider "aws" {
    profile = var.aws_profile
    region = var.aws_region
}

resource "aws_cloudwatch_event_permission" "org_event_bus" {
  principal    = "*"
  statement_id = "OrganizationEventBus"

  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = var.org_id
  }
}

resource "aws_iam_role" "lambda_role" {
    name = "ComplianceRepair"
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
            "Sid": "ComplianceRepair"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_basic_execution_role" {
    role = aws_iam_role.lambda_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_policy_document" {
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
        sid = "ComplianceRepairS3NewBucketMaciePolicy"
        actions = [
            "macie:AssociateS3Resources"
        ]
        resources = ["*"]
    }
    statement {
        sid = "ComplianceRepairConfigRecorderLoggingPolicy"
        actions = [
            "config:StartConfigurationRecorder"
        ]
        resources = ["*"]
    }
    statement {
        sid = "ComplianceRepairAssumePolicy"
        actions = [
            "sts:AssumeRole"
        ]
        resources = ["arn:aws:iam::*:role/ComplianceRepairCrossAccount"]
        condition {
            test = "StringEquals"
            variable = "aws:PrincipalOrgID"
            values = [
                var.org_id
            ]
        }
    }
}

resource "aws_iam_policy" "lambda_iam_policy" {
    name = "ComplianceRepairPolicy"
    path = "/"
    policy = data.aws_iam_policy_document.lambda_policy_document.json
}

resource "aws_iam_role_policy_attachment" "attach_lambda_iam_policy" {
    role = aws_iam_role.lambda_role.name
    policy_arn = aws_iam_policy.lambda_iam_policy.arn
}

resource "aws_lambda_function" "lambda_function" {
    filename = "function.zip"
    function_name = "ComplianceRepair"
    role = aws_iam_role.lambda_role.arn
    handler = "lambda_function.lambda_handler"
    source_code_hash = filebase64sha256("function.zip")
    runtime = "python3.8"
    environment {
        variables = {
            CROSSROLE = var.cross_account_role
        }
    }
}

resource "aws_cloudwatch_event_rule" "password_event_rule" {
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

resource "aws_lambda_permission" "password_permission" {
    statement_id = "AllowFromPasswordPolicyChangeEvent"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.lambda_function.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.password_event_rule.arn
}

resource "aws_cloudwatch_event_target" "password_target" {
    rule = aws_cloudwatch_event_rule.password_event_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.lambda_function.arn
}

resource "aws_cloudwatch_event_rule" "cloudtrail_logging_event_rule" {
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

resource "aws_lambda_permission" "cloudtrail_logging_permission" {
    statement_id = "AllowExecutionFromCloudtrailLoggingDisabled"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.lambda_function.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.cloudtrail_logging_event_rule.arn
}

resource "aws_cloudwatch_event_target" "cloudtrail_logging_target" {
    rule = aws_cloudwatch_event_rule.cloudtrail_logging_event_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.lambda_function.arn
}

resource "aws_cloudwatch_event_rule" "s3_public_event_rule" {
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

resource "aws_lambda_permission" "s3_public_access_permission" {
    statement_id = "AllowExecutionFromS3PublicAccessChange"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.lambda_function.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.s3_public_event_rule.arn
}

resource "aws_cloudwatch_event_target" "s3_public_access_target" {
    rule = aws_cloudwatch_event_rule.s3_public_event_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.lambda_function.arn
}

resource "aws_cloudwatch_event_rule" "newbucket_event_rule" {
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

resource "aws_lambda_permission" "newbucket_permission" {
    statement_id = "AllowExecutionFromS3NewBucket"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.lambda_function.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.newbucket_event_rule.arn
}

resource "aws_cloudwatch_event_target" "newbucket_target" {
    rule = aws_cloudwatch_event_rule.newbucket_event_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.lambda_function.arn
}

resource "aws_cloudwatch_event_rule" "config_recorder_event_rule" {
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

resource "aws_lambda_permission" "config_recorder_permission" {
    statement_id = "AllowExecutionFromConfigRecorderStopped"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.lambda_function.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.config_recorder_event_rule.arn
}

resource "aws_cloudwatch_event_target" "config_recorder_target" {
    rule = aws_cloudwatch_event_rule.config_recorder_event_rule.name
    target_id = "SendToLambda"
    arn = aws_lambda_function.lambda_function.arn
}
