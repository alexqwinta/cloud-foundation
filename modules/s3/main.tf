resource "aws_s3_bucket" "this" {
  bucket        = "${var.name_prefix}-data-bucket"
  force_destroy = true
}

# 1. Block Public Access
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}

# 2. KMS Encryption за допомогою Foundation Key
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = var.default_encryption ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# 3. Версіонування (Захист від перезапису/видалення)
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.versioning ? "Enabled" : "Suspended"
  }
}

# 4. Примусовий TLS (Deny Plaintext HTTP)
resource "aws_s3_bucket_policy" "tls" {
  count  = var.enforce_tls ? 1 : 0
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.this.arn}", "${aws_s3_bucket.this.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

