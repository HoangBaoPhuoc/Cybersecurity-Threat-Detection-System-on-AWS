# Networking
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "threat-detection-vpc"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "threat-detection-public-${count.index}"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "threat-detection-private-${count.index}"
  }
}

data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "bastion_sg" {
  name        = "bastion_sg"
  description = "Allow SSH to Bastion"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

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

  ingress {
    from_port   = 443
    to_port     = 443
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

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "es:*"
        Principal = "*"
        Effect    = "Allow"
        Resource  = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${var.opensearch_domain_name}/*"
      }
    ]
  })
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

# --- DynamoDB Deduplication ---
resource "aws_dynamodb_table" "soar_dedup" {
  name         = "soar-deduplication"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "dedup_id"

  attribute {
    name = "dedup_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# --- WAF IP Set ---
resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "blocked-ips"
  description        = "IPs blocked by SOAR"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  lifecycle {
    ignore_changes = [addresses] # Let Lambda manage this
  }
}

# --- WAF Web ACL ---
resource "aws_wafv2_web_acl" "main" {
  name        = "threat-detection-waf"
  description = "WAF for App Server"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockBadIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockBadIPs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "main-waf"
    sampled_requests_enabled   = true
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.financial_app.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# --- Deny All IAM Policy ---
resource "aws_iam_policy" "deny_all" {
  name        = "soar-deny-all"
  description = "Deny all actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "remediation" {
  filename      = "remediation_payload.zip" # Placeholder
  function_name = "threat-remediation-func"
  role          = aws_iam_role.lambda_role.arn
  handler       = "remediation_lambda.handler"
  runtime       = "python3.11"
}

# --- Blocking Lambda ---
data "archive_file" "block_ip_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/block_ip.py"
  output_path = "${path.module}/block_ip.zip"
}

resource "aws_iam_role" "block_ip_role" {
  name = "block_ip_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "block_ip_policy" {
  name = "block_ip_policy"
  role = aws_iam_role.block_ip_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "block_ip" {
  filename         = data.archive_file.block_ip_zip.output_path
  function_name    = "soar-block-ip"
  role             = aws_iam_role.block_ip_role.arn
  handler          = "block_ip.lambda_handler"
  source_code_hash = data.archive_file.block_ip_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      VPC_ID = aws_vpc.main.id
    }
  }
}

# --- Jira Lambda ---
data "archive_file" "create_jira_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/create_jira.py"
  output_path = "${path.module}/create_jira.zip"
}

resource "aws_lambda_function" "create_jira" {
  filename         = data.archive_file.create_jira_zip.output_path
  function_name    = "soar-create-jira"
  role             = aws_iam_role.block_ip_role.arn # Reusing role for demo simplicity
  handler          = "create_jira.lambda_handler"
  source_code_hash = data.archive_file.create_jira_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      JIRA_URL            = var.jira_url
      JIRA_USER           = var.jira_user
      JIRA_API_TOKEN      = var.jira_api_token
      JIRA_PROJECT_KEY    = var.jira_project_key
      OPENSEARCH_ENDPOINT = aws_opensearch_domain.siem.endpoint
    }
  }
}

# --- Disable User Lambda ---
data "archive_file" "disable_user_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/disable_user.py"
  output_path = "${path.module}/disable_user.zip"
}

resource "aws_lambda_function" "disable_user" {
  filename         = data.archive_file.disable_user_zip.output_path
  function_name    = "soar-disable-user"
  role             = aws_iam_role.block_ip_role.arn # Reuse role for simplicity, add policy below
  handler          = "disable_user.lambda_handler"
  source_code_hash = data.archive_file.disable_user_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10
}

# Add IAM Permission for Disable User
resource "aws_iam_role_policy" "disable_user_policy" {
  name = "disable_user_policy"
  role = aws_iam_role.block_ip_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:DeleteLoginProfile",
          "iam:UpdateLoginProfile"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# SOAR Step Function with Parallel Remediation
resource "aws_sfn_state_machine" "soar_workflow" {
  name     = "threat-response-workflow"
  role_arn = aws_iam_role.lambda_role.arn

  definition = <<EOF
{
  "Comment": "Production SOAR Workflow",
  "StartAt": "Deduplication",
  "States": {
    "Deduplication": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.deduplication.arn}",
      "Next": "CheckDuplicate"
    },
    "CheckDuplicate": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.is_duplicate",
          "BooleanEquals": true,
          "Next": "UpdateExistingTicket"
        }
      ],
      "Default": "CreateTicket"
    },
    "UpdateExistingTicket": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.update_jira.arn}",
      "Parameters": {
        "ticket_id.$": "$.ticket_id",
        "action": "ADD_COMMENT",
        "comment": "Recurring Alert Detected"
      },
      "End": true
    },
    "CreateTicket": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.create_jira.arn}",
      "ResultPath": "$.ticket",
      "Next": "CollectEvidence"
    },
    "CollectEvidence": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.evidence_collector.arn}",
      "ResultPath": "$.evidence",
      "Next": "AttachEvidence"
    },
    "AttachEvidence": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.update_jira.arn}",
      "Parameters": {
        "ticket_id.$": "$.ticket.key",
        "action": "ADD_COMMENT",
        "comment.$": "$.evidence.evidence"
      },
      "ResultPath": null,
      "Next": "DetermineAction"
    },
    "DetermineAction": {
      "Type": "Choice",
      "Choices": [
        {
          "Or": [
            {
              "Variable": "$.severity",
              "StringEquals": "HIGH"
            },
            {
              "Variable": "$.severity",
              "StringEquals": "CRITICAL"
            }
          ],
          "Next": "RequestApproval"
        }
      ],
      "Default": "ManualReview"
    },
    "ManualReview": {
      "Type": "Pass",
      "End": true
    },
    "RequestApproval": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.update_jira.arn}",
        "Payload": {
          "ticket_id.$": "$.ticket.key",
          "action": "ADD_COMMENT",
          "comment": "High Risk Detected. Approval Required: https://console.aws.amazon.com/states/home?region=${var.aws_region}#/statemachines/view/${aws_sfn_state_machine.soar_workflow.arn}?token=$$.Task.Token"
        }
      },
      "Next": "RemediateHighRisk"
    },
    "RemediateHighRisk": {
      "Type": "Parallel",
      "Next": "WaitTTL",
      "Branches": [
        {
          "StartAt": "BlockWAF",
          "States": {
            "BlockWAF": {
              "Type": "Task",
              "Resource": "${aws_lambda_function.block_waf.arn}",
              "End": true
            }
          }
        },
        {
          "StartAt": "RestrictIAM",
          "States": {
            "RestrictIAM": {
              "Type": "Task",
              "Resource": "${aws_lambda_function.restrict_iam.arn}",
              "End": true
            }
          }
        }
      ]
    },
    "WaitTTL": {
      "Type": "Wait",
      "Seconds": 3600,
      "Next": "RollbackRemediation"
    },
    "RollbackRemediation": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.revert_remediation.arn}",
      "End": true
    }
  }
}
EOF
}

# --- VPC Flow Logs ---
resource "aws_flow_log" "main" {
  iam_role_arn         = aws_iam_role.vpc_flow_log_role.arn
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_log.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name = "/aws/vpc/flowlogs/threat-detection-vpc"
}

resource "aws_iam_role" "vpc_flow_log_role" {
  name = "vpc_flow_log_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_log_policy" {
  name = "vpc_flow_log_policy"
  role = aws_iam_role.vpc_flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# --- VPC Flow Logs to S3 (for SIEM) ---
resource "aws_s3_bucket" "vpc_flow_logs" {
  bucket        = "threat-detection-vpc-flow-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_flow_log" "s3" {
  log_destination      = aws_s3_bucket.vpc_flow_logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
}

# --- CloudTrail ---


resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "threat-detection-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AWSCloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = aws_s3_bucket.cloudtrail_logs.arn
      }, {
      Sid       = "AWSCloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl" = "bucket-owner-full-control"
        }
      }
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "threat-detection-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]
}

# --- EC2 IAM Role for S3 Access (SIEM) ---
resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2_s3_siem_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ec2_s3_policy" {
  name = "ec2_s3_siem_policy"
  role = aws_iam_role.ec2_s3_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
          aws_s3_bucket.vpc_flow_logs.arn,
          "${aws_s3_bucket.vpc_flow_logs.arn}/*"
        ]
      },
      {
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.entity_risk_state.arn
        ]
      }
    ]
  })
}

# --- DynamoDB Entity Risk State ---
resource "aws_dynamodb_table" "entity_risk_state" {
  name         = "entity-risk-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "entity_id"

  attribute {
    name = "entity_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "EntityRiskState"
  }
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_siem_profile"
  role = aws_iam_role.ec2_s3_role.name
}

# --- Financial System EC2 ---
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_security_group" "sg_app" {
  name        = "sg_app"
  description = "Security Group for Application Server"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  # For internal testing/demo purposes, allow all internal traffic for now, 
  # or strict rule: Allow Beats to talk to Kafka
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_logstash" {
  name        = "sg_logstash"
  description = "Security Group for Logstash Server"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  # Allow traffic from Kafka/OpenSearch if needed, but Logstash acts as client mostly.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_detection" {
  name        = "sg_detection"
  description = "Security Group for Detection Engine"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_orchestrator" {
  name        = "sg_orchestrator"
  description = "Security Group for SOAR Orchestrator"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  ingress {
    description     = "Allow MCP API from Detection Engine"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_detection.id]
  }
  # Allow internal communication
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- 1. App Server ---
resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_app.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  tags = {
    Name = "app-server"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3 python3-pip openjdk-11-jre-headless
              pip3 install flask requests boto3

              # Install Beats
              curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
              dpkg -i filebeat-8.10.2-amd64.deb
              curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.10.2-amd64.deb
              dpkg -i metricbeat-8.10.2-amd64.deb
              curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.10.2-amd64.deb
              dpkg -i auditbeat-8.10.2-amd64.deb

              # Create Directories
              mkdir -p /opt/financial_app

              # Inject Financial App
              cat <<py > /opt/financial_app/app.py
              ${file("${path.module}/../src/financial_app.py")}
              py

              # Configure Filebeat
              cat <<yml > /etc/filebeat/filebeat.yml
              ${file("${path.module}/../config/filebeat.yml")}
              yml

              # Configure Metricbeat
              cat <<yml > /etc/metricbeat/metricbeat.yml
              ${file("${path.module}/../config/metricbeat.yml")}
              yml

              # Configure Auditbeat
              cat <<yml > /etc/auditbeat/auditbeat.yml
              ${file("${path.module}/../config/auditbeat.yml")}
              yml

              # Appending AWS Module Configuration
              cat <<yml >> /etc/filebeat/filebeat.yml
              
              filebeat.modules:
              - module: aws
                cloudtrail:
                  enabled: true
                  var.bucket_arn: '${aws_s3_bucket.cloudtrail_logs.arn}'
                vpcflow:
                  enabled: true
                  var.bucket_arn: '${aws_s3_bucket.vpc_flow_logs.arn}'
              yml

              BROKERS="${aws_msk_cluster.kafka.bootstrap_brokers_tls}"
              BROKERS_FORMATTED=$(echo $BROKERS | sed 's/,/", "/g')
              sed -i "s/hosts: \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/hosts: [\"$BROKERS_FORMATTED\"]/g" /etc/filebeat/filebeat.yml
              sed -i "s/hosts: \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/hosts: [\"$BROKERS_FORMATTED\"]/g" /etc/metricbeat/metricbeat.yml
              sed -i "s/hosts: \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/hosts: [\"$BROKERS_FORMATTED\"]/g" /etc/auditbeat/auditbeat.yml
              
              # Financial App Service
              cat <<service > /etc/systemd/system/financial-app.service
              [Unit]
              Description=Financial App Simulator
              After=network.target

              [Service]
              User=root
              WorkingDirectory=/opt/financial_app
              ExecStart=/usr/bin/python3 app.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              service

              # Install Wazuh Agent
              curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
              echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
              apt-get update
              WAZUH_MANAGER="${aws_instance.wazuh_manager.private_ip}"
              apt-get install -y wazuh-agent
              sed -i "s/MANAGER_IP/$WAZUH_MANAGER/" /var/ossec/etc/ossec.conf
              systemctl enable wazuh-agent
              systemctl start wazuh-agent

              # Start Services
              systemctl enable filebeat metricbeat auditbeat financial-app
              systemctl start filebeat metricbeat auditbeat financial-app
              EOF
}

# --- 2. Logstash Server ---
resource "aws_instance" "logstash_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_logstash.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name # Needs S3 access? Maybe not, but standardizing.
  associate_public_ip_address = false

  tags = {
    Name = "log-processing-server"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y openjdk-11-jre-headless wget apt-transport-https

              # Install Logstash
              wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
              echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
              apt-get update && apt-get install -y logstash

              # Configure Logstash
              cat <<conf > /etc/logstash/conf.d/logstash.conf
              ${file("${path.module}/../config/logstash.conf")}
              conf

              # Inject Variables into Logstash Config
              BROKERS="${aws_msk_cluster.kafka.bootstrap_brokers_tls}"
              BROKERS_FORMATTED=$(echo $BROKERS | sed 's/,/", "/g')
              OPENSEARCH_ENDPOINT="${aws_opensearch_domain.siem.endpoint}"
              
              sed -i "s/bootstrap_servers => \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/bootstrap_servers => [\"$BROKERS_FORMATTED\"]/g" /etc/logstash/conf.d/logstash.conf
              sed -i "s/hosts => \\[\"https:\\/\\/opensearch-domain:443\"\\]/hosts => [\"https:\\/\\/$OPENSEARCH_ENDPOINT:443\"]/g" /etc/logstash/conf.d/logstash.conf

              # Install Wazuh Agent
              curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
              echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
              apt-get update
              WAZUH_MANAGER="${aws_instance.wazuh_manager.private_ip}"
              apt-get install -y wazuh-agent
              sed -i "s/MANAGER_IP/$WAZUH_MANAGER/" /var/ossec/etc/ossec.conf
              systemctl enable wazuh-agent
              systemctl start wazuh-agent

              # Start Logstash
              systemctl enable logstash
              systemctl start logstash
              EOF
}

# --- 3. Detection Engine ---
resource "aws_instance" "detection_engine" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.small"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_detection.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  tags = {
    Name = "detection-engine"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3 python3-pip
              pip3 install opensearch-py requests boto3

              # Create Directories
              mkdir -p /opt/analysis

              # Analysis Modules
              cat <<py > /opt/analysis/ai_orchestrator.py
              ${file("${path.module}/../src/analysis/ai_orchestrator.py")}
              py

              cat <<py > /opt/analysis/anomaly_detection.py
              ${file("${path.module}/../src/analysis/anomaly_detection.py")}
              py
              
              cat <<py > /opt/analysis/rag_engine.py
              ${file("${path.module}/../src/analysis/rag_engine.py")}
              py

              cat <<py > /opt/analysis/alert_manager.py
              ${file("${path.module}/../src/analysis/alert_manager.py")}
              py
              
              cat <<py > /opt/analysis/configure_opensearch.py
              ${file("${path.module}/../src/analysis/configure_opensearch.py")}
              py
              


              # Service
              cat <<service > /etc/systemd/system/threat-detection.service
              [Unit]
              Description=Threat Detection Engine
              After=network.target

              [Service]
              User=root
              WorkingDirectory=/opt/analysis
              Environment="OPENSEARCH_HOST=${aws_opensearch_domain.siem.endpoint}"
              Environment="OPENSEARCH_PORT=443"
              Environment="MCP_URL=http://${aws_instance.soar_orchestrator.private_ip}:8000"
              Environment="JIRA_API_TOKEN=${var.jira_api_token}"
              Environment="JIRA_PROJECT_KEY=${var.jira_project_key}"
              Environment="OPENAI_API_KEY=${var.openai_api_key}"
              ExecStart=/usr/bin/python3 ai_orchestrator.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              service

              # Install Wazuh Agent
              curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
              echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
              apt-get update
              WAZUH_MANAGER="${aws_instance.wazuh_manager.private_ip}"
              apt-get install -y wazuh-agent
              sed -i "s/MANAGER_IP/$WAZUH_MANAGER/" /var/ossec/etc/ossec.conf
              systemctl enable wazuh-agent
              systemctl start wazuh-agent

              # Start Service
              systemctl enable threat-detection
              systemctl start threat-detection

              # Configure OpenSearch (Run Once, or on every boot if safe)
              # Ideally run in a separate initialization service or just executing here.
              # We background it to not block cloud-init if Opensearch is slow to start
              nohup python3 /opt/analysis/configure_opensearch.py > /var/log/configure_opensearch.log 2>&1 &
              EOF
}

# --- 4. SOAR Orchestrator ---
resource "aws_instance" "soar_orchestrator" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.small"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_orchestrator.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  tags = {
    Name = "soar-orchestrator"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3 python3-pip
              pip3 install opensearch-py requests boto3 flask

              mkdir -p /opt/analysis
              mkdir -p /opt/integration

              # MCP Server
              cat <<py > /opt/integration/mcp_server.py
              ${file("${path.module}/../src/integration/mcp_server.py")}
              py

              # Analysis Modules
              cat <<py > /opt/analysis/ai_orchestrator.py
              ${file("${path.module}/../src/analysis/ai_orchestrator.py")}
              py
              
              cat <<py > /opt/analysis/anomaly_detection.py
              ${file("${path.module}/../src/analysis/anomaly_detection.py")}
              py
              
              cat <<py > /opt/analysis/rag_engine.py
              ${file("${path.module}/../src/analysis/rag_engine.py")}
              py

              cat <<py > /opt/analysis/alert_manager.py
              ${file("${path.module}/../src/analysis/alert_manager.py")}
              py
              


              # Systemd Services

              # MCP Server Service
              cat <<service > /etc/systemd/system/mcp-server.service
              [Unit]
              Description=MCP Server (Mock Threat Intel)
              After=network.target

              [Service]
              User=root
              WorkingDirectory=/opt/integration
              ExecStart=/usr/bin/python3 mcp_server.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              service

              # AI Orchestrator Service
              cat <<service > /etc/systemd/system/ai-orchestrator.service
              [Unit]
              Description=AI Orchestrator
              After=network.target mcp-server.service

              [Service]
              User=root
              WorkingDirectory=/opt/analysis
              Environment="OPENSEARCH_HOST=${aws_opensearch_domain.siem.endpoint}"
              Environment="OPENSEARCH_PORT=443"
              Environment="STEP_FUNCTION_ARN=${aws_sfn_state_machine.soar_workflow.arn}"
              Environment="JIRA_API_TOKEN=${var.jira_api_token}"
              Environment="JIRA_PROJECT_KEY=${var.jira_project_key}"
              Environment="OPENAI_API_KEY=${var.openai_api_key}"
              ExecStart=/usr/bin/python3 ai_orchestrator.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              service

              # Install Wazuh Agent
              curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
              echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
              apt-get update
              WAZUH_MANAGER="${aws_instance.wazuh_manager.private_ip}"
              apt-get install -y wazuh-agent
              sed -i "s/MANAGER_IP/$WAZUH_MANAGER/" /var/ossec/etc/ossec.conf
              systemctl enable wazuh-agent
              systemctl start wazuh-agent

              # Start Services
              systemctl enable mcp-server ai-orchestrator
              systemctl start mcp-server ai-orchestrator
              EOF
}

# --- 5. Wazuh Manager ---

resource "aws_security_group" "sg_wazuh" {
  name        = "sg_wazuh"
  description = "Security Group for Wazuh Manager"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "SSH"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }

  ingress {
    description = "Wazuh Agent Events"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Wazuh Agent Enrollment"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description     = "Wazuh API"
    from_port       = 55000
    to_port         = 55000
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }

  ingress {
    description     = "Wazuh Dashboard"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "wazuh_manager" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_wazuh.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  tags = {
    Name = "wazuh-manager"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y curl apt-transport-https gnupg lsb-release

              # 1. Install Wazuh Manager
              curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
              echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
              apt-get update
              apt-get install -y wazuh-manager wazuh-dashboard wazuh-indexer

              # Basic Configuration (Demo)
              # In production, use wazuh-install.sh or proper config management
              
              systemctl enable wazuh-manager
              systemctl start wazuh-manager
              systemctl enable wazuh-dashboard
              systemctl start wazuh-dashboard
              systemctl enable wazuh-indexer
              systemctl start wazuh-indexer

              # 2. Install Filebeat (Forward Alerts to OpenSearch SIEM)
              curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
              dpkg -i filebeat-8.10.2-amd64.deb

              cat <<yml > /etc/filebeat/filebeat.yml
              filebeat.inputs:
              - type: log
                enabled: true
                paths:
                  - /var/ossec/logs/alerts/alerts.json
                json.keys_under_root: true
                json.overwrite_keys: true
                json.add_error_key: true
                json.message_key: full_log

              output.opensearch:
                hosts: ["${aws_opensearch_domain.siem.endpoint}:443"]
                protocol: "https"
                username: "admin"
                password: "Admin123!" 
                ssl.verification_mode: none
              yml

              systemctl enable filebeat
              systemctl start filebeat
              EOF
}

# Add Internet Gateway for the VPC
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

# NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "threat-detection-nat-gw"
  }
  depends_on = [aws_internet_gateway.gw]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "threat-detection-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "threat-detection-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Bastion Host
resource "aws_instance" "bastion" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public[0].id

  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  associate_public_ip_address = true

  tags = {
    Name = "Bastion-Host"
  }
}

# --- Application Load Balancer (ALB) ---

resource "aws_security_group" "alb_sg" {
  name        = "threat-detection-alb-sg"
  description = "Allow HTTP/HTTPS inbound"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from Internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "threat-detection-alb-sg"
  }
}

resource "aws_lb" "financial_app" {
  name               = "financial-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name = "financial-app-alb"
  }
}

resource "aws_lb_target_group" "financial_app" {
  name     = "financial-app-tg"
  port     = 5000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.financial_app.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.financial_app.arn
  }
}

resource "aws_lb_target_group_attachment" "financial_app" {
  target_group_arn = aws_lb_target_group.financial_app.arn
  target_id        = aws_instance.app_server.id
  port             = 5000
}

# --- AWS Network Firewall ---

# firewall Subnets
resource "aws_subnet" "firewall" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "threat-detection-firewall-${count.index}"
  }
}

# Stateless Rule Group
resource "aws_networkfirewall_rule_group" "stateless" {
  capacity = 100
  name     = "stateless-pass-all"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 10
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              source { address_definition = "0.0.0.0/0" }
              destination { address_definition = "0.0.0.0/0" }
            }
          }
        }
      }
    }
  }
}

# Stateful Rule Group - Domain Filtering
resource "aws_networkfirewall_rule_group" "stateful_domains" {
  capacity = 100
  name     = "stateful-domains"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = [".malicious-site.com", ".botnet-c2.org"]
      }
    }
  }
}

# Stateful Rule Group - Alert on ICMP
resource "aws_networkfirewall_rule_group" "stateful_icmp" {
  capacity = 100
  name     = "stateful-icmp"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      stateful_rule {
        action = "ALERT"
        header {
          direction        = "ANY"
          protocol         = "ICMP"
          destination      = "ANY"
          destination_port = "ANY"
          source           = "ANY"
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:1"
        }
      }
    }
  }
}


# Firewall Policy
resource "aws_networkfirewall_firewall_policy" "main" {
  name = "threat-detection-fw-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateless_rule_group_reference {
      priority     = 10
      resource_arn = aws_networkfirewall_rule_group.stateless.arn
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateful_domains.arn
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateful_icmp.arn
    }
  }
}

# Network Firewall
resource "aws_networkfirewall_firewall" "main" {
  name                = "threat-detection-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall[*].id
    content {
      subnet_id = subnet_mapping.value
    }
  }
}

# Logging
resource "aws_cloudwatch_log_group" "firewall_logs" {
  name = "/aws/network-firewall/threat-detection"
}

resource "aws_networkfirewall_logging_configuration" "main" {
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_logs.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_logs.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}

# --- GuardDuty ---

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# --- Findings Pipeline (EventBridge -> CloudWatch + Lambda) ---

# 1. CloudWatch Log Group for Findings
resource "aws_cloudwatch_log_group" "guardduty_findings" {
  name              = "/aws/events/guardduty/findings"
  retention_in_days = 90
}

# 2. EventBridge Rule
resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  name        = "capture-guardduty-finding"
  description = "Capture all GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

# 3. Target: CloudWatch Logs
resource "aws_cloudwatch_event_target" "log_findings" {
  rule = aws_cloudwatch_event_rule.guardduty_finding.name
  arn  = aws_cloudwatch_log_group.guardduty_findings.arn
}

# 4. Target: Lambda Transformer
resource "aws_cloudwatch_event_target" "lambda_transformer" {
  rule = aws_cloudwatch_event_rule.guardduty_finding.name
  arn  = aws_lambda_function.guardduty_transformer.arn
}

# --- Lambda Transformer (GuardDuty -> OpenSearch) ---

data "archive_file" "guardduty_transformer_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/guardduty_transformer.py"
  output_path = "${path.module}/guardduty_transformer.zip"
}

resource "aws_iam_role" "transformer_role" {
  name = "guardduty_transformer_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "transformer_basic" {
  role       = aws_iam_role.transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "transformer_vpc" {
  role       = aws_iam_role.transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "guardduty_transformer" {
  filename         = data.archive_file.guardduty_transformer_zip.output_path
  function_name    = "guardduty-to-opensearch"
  role             = aws_iam_role.transformer_role.arn
  handler          = "guardduty_transformer.lambda_handler"
  source_code_hash = data.archive_file.guardduty_transformer_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  vpc_config {
    subnet_ids         = [aws_subnet.private[0].id, aws_subnet.private[1].id]
    security_group_ids = [aws_security_group.msk_sg.id] # Reusing SG that allows traffic within VPC
  }

  environment {
    variables = {
      OPENSEARCH_HOST = aws_opensearch_domain.siem.endpoint
    }
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_transformer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_finding.arn
}

# --- AWS Config ---

resource "aws_s3_bucket" "config_bucket" {
  bucket        = "threat-detection-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_iam_role" "config" {
  name = "aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "threat-detection-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "threat-detection-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

# --- Managed Rules ---

resource "aws_config_config_rule" "ssh" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_public" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "root_access" {
  name = "iam-root-access-key-check"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# --- Compliance Pipeline (EventBridge -> CloudWatch + Lambda) ---

# 1. CloudWatch Log Group for Compliance
resource "aws_cloudwatch_log_group" "config_findings" {
  name              = "/aws/events/config/compliance"
  retention_in_days = 90
}

# 2. EventBridge Rule
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "capture-config-compliance"
  description = "Capture AWS Config compliance changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
  })
}

# 3. Target: CloudWatch Logs
resource "aws_cloudwatch_event_target" "log_config" {
  rule = aws_cloudwatch_event_rule.config_compliance.name
  arn  = aws_cloudwatch_log_group.config_findings.arn
}

# 4. Target: Lambda Transformer
resource "aws_cloudwatch_event_target" "lambda_config" {
  rule = aws_cloudwatch_event_rule.config_compliance.name
  arn  = aws_lambda_function.config_transformer.arn
}

# --- Lambda Transformer (Config -> OpenSearch) ---

data "archive_file" "config_transformer_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/config_transformer.py"
  output_path = "${path.module}/config_transformer.zip"
}

resource "aws_iam_role" "config_transformer_role" {
  name = "config_transformer_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_transformer_basic" {
  role       = aws_iam_role.config_transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "config_transformer_vpc" {
  role       = aws_iam_role.config_transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "config_transformer" {
  filename         = data.archive_file.config_transformer_zip.output_path
  function_name    = "config-to-opensearch"
  role             = aws_iam_role.config_transformer_role.arn
  handler          = "config_transformer.lambda_handler"
  source_code_hash = data.archive_file.config_transformer_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  vpc_config {
    subnet_ids         = [aws_subnet.private[0].id, aws_subnet.private[1].id]
    security_group_ids = [aws_security_group.msk_sg.id] # Reusing SG
  }

  environment {
    variables = {
      OPENSEARCH_HOST = aws_opensearch_domain.siem.endpoint
    }
  }
}

resource "aws_lambda_permission" "allow_config_eventbridge" {
  statement_id  = "AllowExecutionFromConfigEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_transformer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance.arn
}

# --- Route53 Resolver Query Logging ---

# 1. CloudWatch Log Group for DNS Queries
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/dns-queries"
  retention_in_days = 90
}

# 1a. CloudWatch Log Resource Policy (Allow Route53 to write logs)
resource "aws_cloudwatch_log_resource_policy" "route53_query_logging_policy" {
  policy_name = "route53-query-logging-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Route53ResolverLogsWrite",
        Effect = "Allow",
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        },
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "${aws_cloudwatch_log_group.dns_queries.arn}:*"
      }
    ]
  })
}

# 2. Resolver Query Log Config
resource "aws_route53_resolver_query_log_config" "main" {
  name            = "threat-detection-dns-logs"
  destination_arn = aws_cloudwatch_log_group.dns_queries.arn
}

# 3. Association with VPC
resource "aws_route53_resolver_query_log_config_association" "main" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main.id
  resource_id                  = aws_vpc.main.id
}

# --- DNS Logs Pipeline (CW Logs -> Lambda -> OpenSearch) ---

# 4. Lambda Transformer
data "archive_file" "dns_transformer_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/dns_transformer.py"
  output_path = "${path.module}/dns_transformer.zip"
}

resource "aws_iam_role" "dns_transformer_role" {
  name = "dns_transformer_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dns_transformer_basic" {
  role       = aws_iam_role.dns_transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "dns_transformer_vpc" {
  role       = aws_iam_role.dns_transformer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "dns_transformer" {
  filename         = data.archive_file.dns_transformer_zip.output_path
  function_name    = "dns-to-opensearch"
  role             = aws_iam_role.dns_transformer_role.arn
  handler          = "dns_transformer.lambda_handler"
  source_code_hash = data.archive_file.dns_transformer_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  vpc_config {
    subnet_ids         = [aws_subnet.private[0].id, aws_subnet.private[1].id]
    security_group_ids = [aws_security_group.msk_sg.id] # Reusing SG
  }

  environment {
    variables = {
      OPENSEARCH_HOST = aws_opensearch_domain.siem.endpoint
    }
  }
}

# 5. Permission for CloudWatch Logs to Invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dns_transformer.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.dns_queries.arn}:*"
}

# 6. Subscription Filter
resource "aws_cloudwatch_log_subscription_filter" "dns_logs_to_lambda" {
  name            = "dns-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.dns_queries.name
  filter_pattern  = "" # All logs
  destination_arn = aws_lambda_function.dns_transformer.arn
  depends_on      = [aws_lambda_permission.allow_cloudwatch_logs]
}
