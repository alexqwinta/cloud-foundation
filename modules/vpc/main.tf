resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags                 = { Name = "${var.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags                 = { Name = "${var.name_prefix}-private-${count.index}" }
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints-sg"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.endpoint_ingress_cidr] # Weak: 0.0.0.0/0, Hardened: 10.20.0.0/16
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_flow_log" "this" {
  count                = var.enable_flow_logs ? 1 : 0
  iam_role_arn         = var.flow_logs_role_arn
  log_destination_type = "cloud-watch-logs"
  log_destination      = var.flow_logs_group_arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
}
