variable "aws_region" {
  description = "AWS Region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "msk_cluster_name" {
  description = "Name of the MSK Cluster"
  type        = string
  default     = "threat-detection-msk"
}

variable "opensearch_domain_name" {
  description = "Name of the OpenSearch Domain"
  type        = string
  default     = "threat-detection-siem"
}

variable "jira_url" {
  description = "URL of your Jira Cloud instance (e.g., https://your-domain.atlassian.net)"
  type        = string
}

variable "jira_user" {
  description = "Email address of the Jira user"
  type        = string
}

variable "jira_api_token" {
  description = "API Token for Jira (create at https://id.atlassian.com/manage-profile/security/api-tokens)"
  type        = string
  sensitive   = true
}

variable "jira_project_key" {
  description = "Project Key where issues will be created (e.g., SEC)"
  type        = string
  default     = "SEC"
}

variable "wazuh_manager_endpoint" {
  description = "Internal endpoint/DNS for Wazuh manager service on EKS"
  type        = string
  default     = "wazuh.svc.cluster.local"
}

variable "eks_cluster_name" {
  description = "Name of the EKS cluster for Wazuh and microservices"
  type        = string
  default     = "nextgen-soc-eks"
}

variable "opensearch_vector_domain_name" {
  description = "OpenSearch domain for vector RAG"
  type        = string
  default     = "threat-detection-vector"
}

variable "playbook_bucket_name" {
  description = "S3 bucket for IR playbooks"
  type        = string
  default     = "threat-detection-playbooks"
}

variable "operator_ui_bucket_name" {
  description = "S3 bucket for the React operator UI"
  type        = string
  default     = "threat-detection-operator-ui"
}
