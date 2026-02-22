# PDR-aligned resources for Next-Gen Cloud-Native SOC on AWS

# --- EKS (Wazuh + Microservices) ---
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_controller" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_ecr_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_cluster" "soc" {
  name     = var.eks_cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = aws_subnet.private[*].id
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_controller
  ]
}

resource "aws_eks_node_group" "soc_nodes" {
  cluster_name    = aws_eks_cluster.soc.name
  node_group_name = "soc-core-nodes"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = aws_subnet.private[*].id

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_ecr_policy
  ]
}

# --- Security Hub -> EventBridge -> Kinesis -> Central Repo ---
resource "aws_securityhub_account" "main" {}

resource "aws_kinesis_stream" "security_hub" {
  name        = "security-hub-stream"
  shard_count = 1
}

resource "aws_iam_role" "eventbridge_kinesis_role" {
  name = "eventbridge-kinesis-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_kinesis_policy" {
  name = "eventbridge-kinesis-policy"
  role = aws_iam_role.eventbridge_kinesis_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["kinesis:PutRecord", "kinesis:PutRecords"]
      Resource = aws_kinesis_stream.security_hub.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "securityhub-findings"
  description = "Route Security Hub findings to Kinesis"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"],
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "securityhub_to_kinesis" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  arn       = aws_kinesis_stream.security_hub.arn
  role_arn  = aws_iam_role.eventbridge_kinesis_role.arn
  target_id = "securityhub-kinesis"
}

resource "aws_s3_bucket" "central_repo" {
  bucket        = "threat-detection-central-repo-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_iam_role" "firehose_role" {
  name = "firehose-securityhub-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "firehose_policy" {
  name = "firehose-securityhub-policy"
  role = aws_iam_role.firehose_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kinesis:DescribeStream", "kinesis:GetShardIterator", "kinesis:GetRecords"],
        Resource = aws_kinesis_stream.security_hub.arn
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload", "s3:GetBucketLocation"],
        Resource = [aws_s3_bucket.central_repo.arn, "${aws_s3_bucket.central_repo.arn}/*"]
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "securityhub_to_s3" {
  name        = "securityhub-firehose"
  destination = "extended_s3"

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.security_hub.arn
    role_arn           = aws_iam_role.firehose_role.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.central_repo.arn
  }
}

# --- SageMaker ---
resource "aws_iam_role" "sagemaker_role" {
  name = "sagemaker-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "sagemaker_full_access" {
  role       = aws_iam_role.sagemaker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_sagemaker_notebook_instance" "soc_notebook" {
  name          = "soc-ml-notebook"
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.sagemaker_role.arn
}

# --- OpenSearch Vector DB ---
resource "aws_opensearch_domain" "vector" {
  domain_name    = var.opensearch_vector_domain_name
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }

  advanced_options = {
    "index.knn" = "true"
  }

  vpc_options {
    subnet_ids         = [aws_subnet.private[0].id]
    security_group_ids = [aws_security_group.msk_sg.id]
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "es:*"
        Principal = "*"
        Effect    = "Allow"
        Resource  = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${var.opensearch_vector_domain_name}/*"
      }
    ]
  })
}

# --- Playbooks S3 ---
resource "aws_s3_bucket" "playbooks" {
  bucket        = "${var.playbook_bucket_name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_object" "playbook_default" {
  bucket = aws_s3_bucket.playbooks.id
  key    = "playbooks/default.md"
  source = "${path.module}/../playbooks/default.md"
}

resource "aws_s3_object" "playbook_privileged" {
  bucket = aws_s3_bucket.playbooks.id
  key    = "playbooks/privileged_account.md"
  source = "${path.module}/../playbooks/privileged_account.md"
}

resource "aws_s3_object" "playbook_network" {
  bucket = aws_s3_bucket.playbooks.id
  key    = "playbooks/network_abuse.md"
  source = "${path.module}/../playbooks/network_abuse.md"
}

# --- Lambda: Risk Scoring ---
data "archive_file" "risk_engine_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/analysis/risk_engine.py"
  output_path = "${path.module}/risk_engine.zip"
}

resource "aws_iam_role" "risk_lambda_role" {
  name = "risk-scoring-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "risk_lambda_policy" {
  name = "risk-lambda-policy"
  role = aws_iam_role.risk_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
        Resource = aws_dynamodb_table.entity_risk_state.arn
      },
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "risk_scoring" {
  filename         = data.archive_file.risk_engine_zip.output_path
  function_name    = "risk-scoring"
  role             = aws_iam_role.risk_lambda_role.arn
  handler          = "risk_engine.lambda_handler"
  source_code_hash = data.archive_file.risk_engine_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      CRITICAL_THRESHOLD     = "70"
      CRITICAL_WEBHOOK_URL   = "${aws_apigatewayv2_api.bedrock_webhook.api_endpoint}/critical"
      DECAY_FACTOR           = "0.98"
      DECAY_TIME_UNIT_SECONDS = "3600"
    }
  }
}

# --- Lambda: Bedrock Agentic AI ---
data "archive_file" "bedrock_agent_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/remediation/bedrock_agent_lambda.py"
  output_path = "${path.module}/bedrock_agent.zip"
}

resource "aws_iam_role" "bedrock_lambda_role" {
  name = "bedrock-agent-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_lambda_policy" {
  name = "bedrock-agent-policy"
  role = aws_iam_role.bedrock_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"],
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject"],
        Resource = "${aws_s3_bucket.playbooks.arn}/*"
      },
      {
        Effect = "Allow"
        Action = ["es:ESHttpPost", "es:ESHttpGet"],
        Resource = "${aws_opensearch_domain.vector.arn}/*"
      },
      {
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"],
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_vpc_access" {
  role       = aws_iam_role.bedrock_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "bedrock_agent" {
  filename         = data.archive_file.bedrock_agent_zip.output_path
  function_name    = "bedrock-agent"
  role             = aws_iam_role.bedrock_lambda_role.arn
  handler          = "bedrock_agent_lambda.lambda_handler"
  source_code_hash = data.archive_file.bedrock_agent_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  vpc_config {
    subnet_ids         = [aws_subnet.private[0].id, aws_subnet.private[1].id]
    security_group_ids = [aws_security_group.msk_sg.id]
  }

  environment {
    variables = {
      OPENSEARCH_ENDPOINT = aws_opensearch_domain.vector.endpoint
      OPENSEARCH_INDEX    = "ir-playbooks"
      PLAYBOOK_BUCKET     = aws_s3_bucket.playbooks.id
      DEFAULT_PLAYBOOK_KEY = "playbooks/default.md"
      JIRA_MCP_URL         = "${aws_apigatewayv2_api.jira_mcp.api_endpoint}"
      LAMBDA_BLOCK_WAF_ARN  = aws_lambda_function.block_waf.arn
      LAMBDA_RESTRICT_IAM_ARN = aws_lambda_function.restrict_iam.arn
      LAMBDA_RUN_SSM_ARN      = aws_lambda_function.ssm_runbook.arn
      LAMBDA_QUARANTINE_SG_ARN = aws_lambda_function.quarantine_sg.arn
      ALLOWED_ACTIONS         = "BLOCK_WAF,RESTRICT_IAM,RUN_SSM,QUARANTINE_SG"
    }
  }
}

# --- Jira MCP Lambda + API Gateway ---
data "archive_file" "jira_mcp_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/integration/jira_mcp_lambda.py"
  output_path = "${path.module}/jira_mcp.zip"
}

resource "aws_iam_role" "jira_mcp_role" {
  name = "jira-mcp-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "jira_mcp_policy" {
  name = "jira-mcp-policy"
  role = aws_iam_role.jira_mcp_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "jira_mcp" {
  filename         = data.archive_file.jira_mcp_zip.output_path
  function_name    = "jira-mcp"
  role             = aws_iam_role.jira_mcp_role.arn
  handler          = "jira_mcp_lambda.lambda_handler"
  source_code_hash = data.archive_file.jira_mcp_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      JIRA_URL         = var.jira_url
      JIRA_USER        = var.jira_user
      JIRA_API_TOKEN   = var.jira_api_token
      JIRA_PROJECT_KEY = var.jira_project_key
    }
  }
}

resource "aws_apigatewayv2_api" "jira_mcp" {
  name          = "jira-mcp-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "jira_mcp_integration" {
  api_id                 = aws_apigatewayv2_api.jira_mcp.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.jira_mcp.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "jira_mcp_tickets" {
  api_id    = aws_apigatewayv2_api.jira_mcp.id
  route_key = "POST /tickets"
  target    = "integrations/${aws_apigatewayv2_integration.jira_mcp_integration.id}"
}

resource "aws_apigatewayv2_route" "jira_mcp_health" {
  api_id    = aws_apigatewayv2_api.jira_mcp.id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.jira_mcp_integration.id}"
}

resource "aws_apigatewayv2_stage" "jira_mcp_stage" {
  api_id      = aws_apigatewayv2_api.jira_mcp.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "jira_mcp_apigw" {
  statement_id  = "AllowAPIGatewayInvokeJiraMcp"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.jira_mcp.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.jira_mcp.execution_arn}/*/*"
}

# --- Lambda: SSM Runbook ---
data "archive_file" "ssm_runbook_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/ssm_runbook.py"
  output_path = "${path.module}/ssm_runbook.zip"
}

resource "aws_iam_role" "ssm_runbook_role" {
  name = "ssm-runbook-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ssm_runbook_policy" {
  name = "ssm-runbook-policy"
  role = aws_iam_role.ssm_runbook_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ssm:StartAutomationExecution"],
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "ssm_runbook" {
  filename         = data.archive_file.ssm_runbook_zip.output_path
  function_name    = "soar-ssm-runbook"
  role             = aws_iam_role.ssm_runbook_role.arn
  handler          = "ssm_runbook.lambda_handler"
  source_code_hash = data.archive_file.ssm_runbook_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  environment {
    variables = {
      SSM_RUNBOOK_NAME = "AWS-RunShellScript"
    }
  }
}

# --- Lambda: Quarantine SG ---
data "archive_file" "quarantine_sg_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/soar/quarantine_sg.py"
  output_path = "${path.module}/quarantine_sg.zip"
}

resource "aws_iam_role" "quarantine_sg_role" {
  name = "quarantine-sg-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "quarantine_sg_policy" {
  name = "quarantine-sg-policy"
  role = aws_iam_role.quarantine_sg_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ec2:ModifyInstanceAttribute"],
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "quarantine_sg" {
  filename         = data.archive_file.quarantine_sg_zip.output_path
  function_name    = "soar-quarantine-sg"
  role             = aws_iam_role.quarantine_sg_role.arn
  handler          = "quarantine_sg.lambda_handler"
  source_code_hash = data.archive_file.quarantine_sg_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.sg_detection.id
    }
  }
}

# --- Operator UI (S3 + Lambda Proxy + API Gateway) ---
resource "aws_s3_bucket" "operator_ui" {
  bucket        = "${var.operator_ui_bucket_name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_object" "ui_index" {
  bucket = aws_s3_bucket.operator_ui.id
  key    = "index.html"
  source = "${path.module}/../frontend/dist/index.html"
  content_type = "text/html"
}

resource "aws_s3_object" "ui_app_js" {
  bucket = aws_s3_bucket.operator_ui.id
  key    = "app.js"
  source = "${path.module}/../frontend/dist/app.js"
  content_type = "application/javascript"
}

resource "aws_s3_object" "ui_styles" {
  bucket = aws_s3_bucket.operator_ui.id
  key    = "styles.css"
  source = "${path.module}/../frontend/dist/styles.css"
  content_type = "text/css"
}

data "archive_file" "ui_proxy_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/frontend/ui_proxy_lambda.py"
  output_path = "${path.module}/ui_proxy.zip"
}

resource "aws_iam_role" "ui_proxy_role" {
  name = "ui-proxy-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ui_proxy_policy" {
  name = "ui-proxy-policy"
  role = aws_iam_role.ui_proxy_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:GetObject"],
        Resource = "${aws_s3_bucket.operator_ui.arn}/*"
      },
      {
        Effect = "Allow",
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "ui_proxy" {
  filename         = data.archive_file.ui_proxy_zip.output_path
  function_name    = "operator-ui-proxy"
  role             = aws_iam_role.ui_proxy_role.arn
  handler          = "ui_proxy_lambda.lambda_handler"
  source_code_hash = data.archive_file.ui_proxy_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      UI_BUCKET = aws_s3_bucket.operator_ui.id
    }
  }
}

resource "aws_apigatewayv2_api" "operator_ui" {
  name          = "operator-ui-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "operator_ui_integration" {
  api_id                 = aws_apigatewayv2_api.operator_ui.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ui_proxy.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "operator_ui_root" {
  api_id    = aws_apigatewayv2_api.operator_ui.id
  route_key = "GET /"
  target    = "integrations/${aws_apigatewayv2_integration.operator_ui_integration.id}"
}

resource "aws_apigatewayv2_route" "operator_ui_proxy" {
  api_id    = aws_apigatewayv2_api.operator_ui.id
  route_key = "GET /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.operator_ui_integration.id}"
}

resource "aws_apigatewayv2_stage" "operator_ui_stage" {
  api_id      = aws_apigatewayv2_api.operator_ui.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "operator_ui_apigw" {
  statement_id  = "AllowAPIGatewayInvokeOperatorUI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ui_proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.operator_ui.execution_arn}/*/*"
}

# --- API Gateway: Bedrock Webhook ---
resource "aws_apigatewayv2_api" "bedrock_webhook" {
  name          = "bedrock-webhook-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "bedrock_integration" {
  api_id                 = aws_apigatewayv2_api.bedrock_webhook.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.bedrock_agent.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "bedrock_route" {
  api_id    = aws_apigatewayv2_api.bedrock_webhook.id
  route_key = "POST /critical"
  target    = "integrations/${aws_apigatewayv2_integration.bedrock_integration.id}"
}

resource "aws_apigatewayv2_stage" "bedrock_stage" {
  api_id      = aws_apigatewayv2_api.bedrock_webhook.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "bedrock_apigw" {
  statement_id  = "AllowAPIGatewayInvokeBedrock"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bedrock_agent.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.bedrock_webhook.execution_arn}/*/*"
}

# --- ELK Stack (Elasticsearch + Kibana) ---
resource "aws_security_group" "sg_elk" {
  name        = "sg_elk"
  description = "Security Group for Elasticsearch/Kibana"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 9200
    to_port         = 9200
    protocol        = "tcp"
    cidr_blocks     = [var.vpc_cidr]
  }

  ingress {
    from_port       = 5601
    to_port         = 5601
    protocol        = "tcp"
    cidr_blocks     = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "elk_stack" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.private[0].id

  vpc_security_group_ids      = [aws_security_group.sg_elk.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  tags = {
    Name = "elk-stack"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y openjdk-11-jre-headless wget apt-transport-https

              wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
              echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
              apt-get update
              apt-get install -y elasticsearch kibana

              systemctl enable elasticsearch
              systemctl start elasticsearch
              systemctl enable kibana
              systemctl start kibana
              EOF
}
