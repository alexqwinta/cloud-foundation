resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/${var.name_prefix}-flow-logs"
  retention_in_days = var.retention_days
}

resource "aws_iam_role" "flow" {
  name = "${var.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_policy" {
  name = "${var.name_prefix}-flow-logs-policy"
  role = aws_iam_role.flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AllowFlowLogging"
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ]
          Resource = "*"
        }
      ],
      var.deny_destructive ? [
        {
          Sid    = "FlowLogsDenyDestructive"
          Effect = "Deny"
          Action = [
            "s3:DeleteBucket",
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

