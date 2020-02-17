variable "aws_profile" {
    description = "AWS profile to launch"
    default = "aws-security"
}

variable "aws_region" {
    description = "AWS region to launch into"
    default = "us-east-1"
}

variable "org_id" {
    description = "AWS organization ID"
    default = "o-m0xjofsnak"
}

variable "cross_account_role" {
    description = "Compliance Repair Cross Account Role"
    default = "ComplianceRepairCrossAccount"
}
