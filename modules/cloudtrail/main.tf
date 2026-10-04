resource "aws_s3_bucket" "trail" {
  bucket        = "${var.name_prefix}-audit-trail-logs"
  force_destroy = true
}

# Бакет для аудіту захищається тими ж прапорцями, що й основний дата-бакет
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = var.versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_policy" "trail_policy" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AWSCloudTrailAclCheck"
          Effect    = "Allow"
          Principal = { Service = "cloudtrail.amazonaws.com" }
          Action    = "s3:GetBucketAcl"
          Resource  = "${aws_s3_bucket.trail.arn}"
        },
        {
          Sid       = "AWSCloudTrailWrite"
          Effect    = "Allow"
          Principal = { Service = "cloudtrail.amazonaws.com" }
          Action    = "s3:PutObject"
          Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${var.account_id}/*"
          Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
        }
      ],
      var.enforce_tls ? [
        {
          Sid       = "EnforceTLSAudit"
          Effect    = "Deny"
          Principal = "*"
          Action    = "s3:*"
          Resource  = ["${aws_s3_bucket.trail.arn}", "${aws_s3_bucket.trail.arn}/*"]
          Condition = { Bool = { "aws:SecureTransport" = "false" } }
        }
      ] : []
    )
  })
}

resource "aws_cloudtrail" "this" {
  name                          = "${var.name_prefix}-account-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = var.multi_region
  enable_log_file_validation    = var.log_file_validation
  #kms_key_id                    = var.use_kms ? var.kms_key_arn : null
  kms_key_id = var.kms_key_arn

  # Явна залежність, без якої Trail впаде при першому створенні
  depends_on = [aws_s3_bucket_policy.trail_policy]

  dynamic "event_selector" {
    for_each = var.data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:aws:s3:::"] # Логування об'єктного рівня (фіксація T1530)
      }
    }
  }
}

