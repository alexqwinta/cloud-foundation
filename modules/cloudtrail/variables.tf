variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }
variable "multi_region" { type = bool }
variable "log_file_validation" { type = bool }
variable "data_events" { type = bool }
variable "use_kms" { type = bool }
variable "kms_key_arn" { type = string }
variable "enforce_tls" { type = bool }
variable "versioning" { type = bool }

