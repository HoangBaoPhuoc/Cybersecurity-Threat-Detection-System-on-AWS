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
