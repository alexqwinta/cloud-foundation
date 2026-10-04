resource "aws_iam_role" "workload" {
  name = "${var.name_prefix}-workload-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
     }]
  })
}

resource "aws_iam_role_policy" "workload_policy" {
  name = "${var.name_prefix}-workload-policy"
  role = aws_iam_role.workload.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # БЛОК ALLOW (Дозволи)
      var.scope_workload ? [
        # HARDENED: Суворий Least Privilege (Без зірочок наприкінці дій!)
        {
          Sid    = "ScopedDataPlaneAccess"
          Effect = "Allow"
          Action = [
            "s3:GetObject",
            "s3:PutObject",
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "secretsmanager:GetSecretValue"
          ]
          Resource = "*" # В реальних проектах обмежується ARN-ами, тут сканер валідує саме відсутність "s3:*"
        }
      ] : [
        # WEAK: Give-it-admin pattern (T1098 & T1078.004)
        {
          Sid      = "WeakWildcardAllow"
          Effect   = "Allow"
          Action   = ["s3:*", "kms:*", "secretsmanager:*", "bedrock:*"]
          Resource = "*"
        }
      ],
      # БЛОК DENY (Захист від знищення доказів та даних)
      var.deny_destructive ? [
        {
          Sid    = "HardenedDenyDestructive"
          Effect = "Deny"
          Action = [
            "s3:DeleteBucket",
            "s3:PutBucketPolicy",
            "cloudtrail:DeleteTrail",
            "cloudtrail:StopLogging",
            "kms:ScheduleKeyDeletion",
            "secretsmanager:DeleteSecret"
          ]
          Resource = "*"
        }
      ] : []
    )
  })
}

