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
        Action = "es:*"
        Principal = "*"
        Effect = "Allow"
        Resource = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${var.opensearch_domain_name}/*"
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
      Action = "sts:AssumeRole"
      Effect = "Allow"
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
          "logs:PutLogEvents"
        ]
        Effect = "Allow"
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
      JIRA_URL         = var.jira_url
      JIRA_USER        = var.jira_user
      JIRA_API_TOKEN   = var.jira_api_token
      JIRA_PROJECT_KEY = var.jira_project_key
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
        Effect = "Allow"
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
  "Comment": "Automated Threat Response Workflow (Network + Identity)",
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
          "Or": [
            {
              "Variable": "$.severity",
              "StringEquals": "HIGH"
            },
            {
              "Variable": "$.severity",
              "StringEquals": "CRITICAL"
            },
            {
              "Variable": "$.risk_score",
              "NumericGreaterThanEquals": 0.8
            }
          ],
          "Next": "RemediateHighRisk"
        }
      ],
      "Default": "CreateTicket"
    },
    "RemediateHighRisk": {
      "Type": "Parallel",
      "Next": "CreateTicket",
      "Branches": [
        {
          "StartAt": "BlockIP",
          "States": {
            "BlockIP": {
              "Type": "Task",
              "Resource": "${aws_lambda_function.block_ip.arn}",
              "End": true
            }
          }
        },
        {
          "StartAt": "DisableUser",
          "States": {
            "DisableUser": {
              "Type": "Task",
              "Resource": "${aws_lambda_function.disable_user.arn}",
              "End": true
            }
          }
        }
      ]
    },
    "CreateTicket": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.create_jira.arn}",
      "End": true
    }
  }
}
EOF
}

# --- VPC Flow Logs ---
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.vpc_flow_log_role.arn
  log_destination_type = "cloud-watch-logs"
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name = "/aws/vpc/flowlogs/threat-detection-vpc"
}

resource "aws_iam_role" "vpc_flow_log_role" {
  name = "vpc_flow_log_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
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
      Effect = "Allow"
      Resource = "*"
    }]
  })
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
      Sid    = "AWSCloudTrailAclCheck"
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action   = "s3:GetBucketAcl"
      Resource = aws_s3_bucket.cloudtrail_logs.arn
    }, {
      Sid    = "AWSCloudTrailWrite"
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
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
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
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

resource "aws_security_group" "financial_sg" {
  name        = "financial_sg"
  description = "Allow SSH and HTTP"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }
  ingress {
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
}

resource "aws_instance" "financial_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id 
  
  vpc_security_group_ids = [aws_security_group.financial_sg.id]
  associate_public_ip_address = true 

  tags = {
    Name = "Financial-System-Server"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3 python3-pip openjdk-11-jre-headless
              pip3 install opensearch-py flask requests boto3

              # Install Beats
              curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
              dpkg -i filebeat-8.10.2-amd64.deb
              curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.10.2-amd64.deb
              dpkg -i metricbeat-8.10.2-amd64.deb
              curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.10.2-amd64.deb
              dpkg -i auditbeat-8.10.2-amd64.deb

              # Install Logstash
              wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
              echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
              apt-get update && apt-get install -y logstash

              # Create Directories
              mkdir -p /opt/financial_app
              mkdir -p /opt/analysis
              mkdir -p /opt/integration

              # --- Inject Source Code ---
              
              # Financial App
              cat <<py > /opt/financial_app/app.py
              ${file("${path.module}/../src/financial_app.py")}
              py
              
              # MCP Server
              cat <<py > /opt/integration/mcp_server.py
              ${file("${path.module}/../src/integration/mcp_server.py")}
              py

              # Analysis Modules
              cat <<py > /opt/analysis/anomaly_detection.py
              ${file("${path.module}/../src/analysis/anomaly_detection.py")}
              py
              
              cat <<py > /opt/analysis/threat_intel.py
              ${file("${path.module}/../src/analysis/threat_intel.py")}
              py

              cat <<py > /opt/analysis/alert_manager.py
              ${file("${path.module}/../src/analysis/alert_manager.py")}
              py

              cat <<py > /opt/analysis/detection_runner.py
              ${file("${path.module}/../src/analysis/detection_runner.py")}
              py
              
              # --- Configuration ---

              # Configure Filebeat
              cat <<yml > /etc/filebeat/filebeat.yml
              ${file("${path.module}/../config/filebeat.yml")}
              yml

              BROKERS="${aws_msk_cluster.kafka.bootstrap_brokers_tls}"
              BROKERS_FORMATTED=$(echo $BROKERS | sed 's/,/", "/g')
              sed -i "s/hosts: \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/hosts: [\"$BROKERS_FORMATTED\"]/g" /etc/filebeat/filebeat.yml
              
              # Configure Logstash
              cat <<conf > /etc/logstash/conf.d/logstash.conf
              ${file("${path.module}/../config/logstash.conf")}
              conf
              
              # Inject Variables into Logstash Config
              OPENSEARCH_ENDPOINT="${aws_opensearch_domain.siem.endpoint}"
              sed -i "s/bootstrap_servers => \\[\"kafka-broker-1:9092\", \"kafka-broker-2:9092\"\\]/bootstrap_servers => [\"$BROKERS_FORMATTED\"]/g" /etc/logstash/conf.d/logstash.conf
              sed -i "s/hosts => \\[\"https:\\/\\/opensearch-domain:443\"\\]/hosts => [\"https:\\/\\/$OPENSEARCH_ENDPOINT:443\"]/g" /etc/logstash/conf.d/logstash.conf

              # --- Systemd Services ---

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

              # Detection Runner Service
              cat <<service > /etc/systemd/system/threat-detection.service
              [Unit]
              Description=Threat Detection Runner
              After=network.target

              [Service]
              User=root
              WorkingDirectory=/opt/analysis
              Environment="OPENSEARCH_HOST=$OPENSEARCH_ENDPOINT"
              Environment="OPENSEARCH_PORT=443"
              Environment="JIRA_API_TOKEN=${var.jira_api_token}"
              Environment="JIRA_PROJECT_KEY=${var.jira_project_key}"
              Environment="OPENAI_API_KEY=${var.openai_api_key}"
              ExecStart=/usr/bin/python3 ai_orchestrator.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              service

              # Start All Services
              systemctl enable filebeat metricbeat auditbeat logstash mcp-server threat-detection
              systemctl start filebeat metricbeat auditbeat logstash mcp-server threat-detection
              
              # Run Financial App (Fin App is simple script, running in background is fine)
              nohup python3 /opt/financial_app/app.py > /dev/null 2>&1 &
              EOF
}

# Add Internet Gateway for the VPC
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.public.id
}
