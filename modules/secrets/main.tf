resource "aws_secretsmanager_secret" "this" {
  name                    = "${var.name_prefix}-database-secret"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = 0
}
