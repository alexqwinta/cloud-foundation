variable "project" {
  type        = string
  description = "Project name for resource naming"
}

variable "environment" {
  type        = string
  description = "Deployment environment (e.g., dev, baseline, prod)"
}

variable "vpc_cidr" {
  type        = string
  description = "The main CIDR block for the VPC"
}

variable "azs" {
  type        = list(string)
  description = "List of availability zones"
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public subnets"
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private subnets"
}

variable "ssh_ingress_cidr" {
  type        = string
  description = "Allowed ingress CIDR for security group endpoints"
}

variable "vpc_flow_logs" {
  type        = bool
  description = "Enable or disable VPC flow logs"
}

variable "kms_strict_key_policy" {
  type        = bool
  description = "Enable strict KMS key policy"
}

variable "kms_allow_cloudtrail" {
  type        = bool
  description = "Grant CloudTrail access to the KMS key"
}

variable "iam_deny_destructive" {
  type        = bool
  description = "Enable explicit Deny for destructive IAM actions"
}

variable "iam_scope_workload" {
  type        = bool
  description = "Restrict workload IAM role permissions"
}

variable "s3_block_public_access" {
  type        = bool
  description = "Enable S3 block public access"
}

variable "s3_default_encryption" {
  type        = bool
  description = "Enable default S3 bucket encryption"
}

variable "s3_enforce_tls" {
  type        = bool
  description = "Enforce TLS/SSL for S3 data access"
}

variable "s3_versioning" {
  type        = bool
  description = "Enable versioning for S3 buckets"
}

variable "cloudtrail_multi_region" {
  type        = bool
  description = "Enable multi-region trail logging"
}

variable "cloudtrail_log_file_validation" {
  type        = bool
  description = "Enable log file integrity validation"
}

variable "cloudtrail_data_events" {
  type        = bool
  description = "Enable CloudTrail S3 data events logging"
}

variable "cloudtrail_use_kms" {
  type        = bool
  description = "Encrypt CloudTrail log files using the KMS key"
}

variable "log_retention_days" {
  type        = number
  description = "Number of days to retain CloudWatch logs"
}

variable "region" {
  type        = string
  description = "The AWS region to deploy into"
}
