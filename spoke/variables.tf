variable "aws_profile" {
    description = "AWS profile"
    default = "aws-spoke"
}

variable "aws_region" {
    description = "AWS region to launch into"
    default = "us-east-1"
}

variable "org_id" {
    description = "AWS organization ID"
    default = "o-m0xjofsnak"
}

variable "event_bus_arn" {
    description = "CloudWatch event bus ARN"
    default = "arn:aws:events:us-east-1:891559086132:event-bus/default"
}

variable "cross_account_role_arn" {
    description = "Compliance Repair Main Execution Role"
    default = "arn:aws:iam::891559086132:role/ComplianceRepair"
}