resource "aws_kms_key" "this" {
  description         = "Shared CMK for Foundation"
  enable_key_rotation = var.strict_key_policy
  policy              = data.aws_iam_policy_document.this.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}-key"
  target_key_id = aws_kms_key.this.key_id
}

data "aws_iam_policy_document" "this" {
  statement {
    sid       = "EnableRootFullAccess"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  dynamic "statement" {
    for_each = var.strict_key_policy ? [1] : []
    content {
      sid       = "WorkloadUse"
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = [var.workload_role_arn != "" ? var.workload_role_arn : "*"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.allow_cloudtrail ? [1] : []
    content {
      sid       = "AllowCloudTrail"
      actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
    }
  }
}

