# Networking
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "threat-detection-vpc"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "threat-detection-private-${count.index}"
  }
}

data "aws_availability_zones" "available" {}

resource "aws_security_group" "msk_sg" {
  name        = "msk_sg"
  description = "Allow inbound traffic for MSK"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# AWS MSK Cluster
resource "aws_msk_cluster" "kafka" {
  cluster_name           = var.msk_cluster_name
  kafka_version          = "3.2.0"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = aws_subnet.private[*].id
    security_groups = [aws_security_group.msk_sg.id]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
    }
  }

  tags = {
    Name = "threat-detection-kafka"
  }
}

# AWS OpenSearch
resource "aws_opensearch_domain" "siem" {
  domain_name    = var.opensearch_domain_name
  engine_version = "OpenSearch_2.7"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  vpc_options {
    subnet_ids         = [aws_subnet.private[0].id]
    security_group_ids = [aws_security_group.msk_sg.id] # Reusing SG for simplicity in example
  }
}

# Remediation Lambda
resource "aws_iam_role" "lambda_role" {
  name = "remediation_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_lambda_function" "remediation" {
  filename      = "remediation_payload.zip" # Placeholder
  function_name = "threat-remediation-func"
  role          = aws_iam_role.lambda_role.arn
  handler       = "remediation_lambda.handler"
  runtime       = "python3.11"
}

# SOAR Step Function
resource "aws_sfn_state_machine" "soar_workflow" {
  name     = "threat-response-workflow"
  role_arn = aws_iam_role.lambda_role.arn # Reusing role for simplicity

  definition = <<EOF
{
  "Comment": "Automated Threat Response Workflow",
  "StartAt": "AnalyzeThreat",
  "States": {
    "AnalyzeThreat": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.remediation.arn}",
      "Next": "DetermineAction"
    },
    "DetermineAction": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.severity",
          "StringEquals": "HIGH",
          "Next": "BlockIP"
        }
      ],
      "Default": "LogIncident"
    },
    "BlockIP": {
      "Type": "Pass",
      "Result": "IP Blocked",
      "End": true
    },
    "LogIncident": {
      "Type": "Pass",
      "Result": "Incident Logged",
      "End": true
    }
  }
}
EOF
}
