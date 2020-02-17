provider "aws" {
    profile = var.aws_profile
    region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "events_iam_role" {
    name = "CloudWatchEventsBusRole"
    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": ["sts:AssumeRole"],
            "Principal": {
                "Service": "events.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": "CloudWatchEventsBusRole"
        }
    ]
}
EOF
}

data "aws_iam_policy_document" "events_iam_policy_document" {
    statement {
        sid = "CloudWatchEventBusPolicy"
        actions = [
            "events:PutEvents"
        ]
        resources = [
            var.event_bus_arn
        ]
    }
}

resource "aws_iam_policy" "events_iam_policy" {
    name = "CloudWatchEventsBusRolePolicy"
    path = "/"
    policy = data.aws_iam_policy_document.events_iam_policy_document.json
}

resource "aws_iam_role_policy_attachment" "events_iam_role_policy_attachment" {
    role = aws_iam_role.events_iam_role.name
    policy_arn = aws_iam_policy.events_iam_policy.arn
}

data "aws_iam_policy_document" "lambda_cross_account_trust_document" {
    statement {
        actions = ["sts:AssumeRole"]
        principals {
            type = "AWS"
            identifiers = [var.cross_account_role_arn]
        }
    }
}

resource "aws_iam_role" "lambda_cross_account_role" {
    name = "ComplianceRepairCrossAccount"
    path = "/"
    assume_role_policy = data.aws_iam_policy_document.lambda_cross_account_trust_document.json
}


data "aws_iam_policy_document" "lambda_cross_account_policy_document" {
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
}

resource "aws_iam_policy" "lambda_cross_account_policy" {
    name = "ComplianceRepairPolicy"
    path = "/"
    policy = data.aws_iam_policy_document.lambda_cross_account_policy_document.json
}

resource "aws_iam_role_policy_attachment" "attach_lambda_cross_account_policy" {
    role = aws_iam_role.lambda_cross_account_role.name
    policy_arn = aws_iam_policy.lambda_cross_account_policy.arn
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

resource "aws_cloudwatch_event_target" "password_target" {
    rule = aws_cloudwatch_event_rule.password_event_rule.name
    target_id = "SendToLambda"
    arn = var.event_bus_arn
    role_arn = aws_iam_role.events_iam_role.arn
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

resource "aws_cloudwatch_event_target" "cloudtrail_logging_target" {
    rule = aws_cloudwatch_event_rule.cloudtrail_logging_event_rule.name
    target_id = "SendToLambda"
    arn = var.event_bus_arn
    role_arn = aws_iam_role.events_iam_role.arn
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

resource "aws_cloudwatch_event_target" "s3_public_access_target" {
    rule = aws_cloudwatch_event_rule.s3_public_event_rule.name
    target_id = "SendToLambda"
    arn = var.event_bus_arn
    role_arn = aws_iam_role.events_iam_role.arn
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

resource "aws_cloudwatch_event_target" "newbucket_target" {
    rule = aws_cloudwatch_event_rule.newbucket_event_rule.name
    target_id = "SendToLambda"
    arn = var.event_bus_arn
    role_arn = aws_iam_role.events_iam_role.arn
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

resource "aws_cloudwatch_event_target" "config_recorder_target" {
    rule = aws_cloudwatch_event_rule.config_recorder_event_rule.name
    target_id = "SendToLambda"
    arn = var.event_bus_arn
    role_arn = aws_iam_role.events_iam_role.arn
}
