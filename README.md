# SIEM/SOAR - AI-Powered Cybersecurity Threat Detection System on AWS

## 1. System Overview
 This project defines a cloud-native Cybersecurity Threat Detection System deployed on AWS. It leverages a modern SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) architecture enhanced with Artificial Intelligence to detect, analyze, and respond to sophisticated security threats in real-time.

 Key capabilities include:
 - **Real-time Ingestion**: High-throughput log and metric streaming.
 - **AI-Driven Detection**: Utilizing Machine Learning for anomaly detection and Generative AI for threat enrichment.
 - **Automated Response**: Immediate remedial actions via SOAR workflows.
 - **Incident Management**: Seamless integration with Jira for incident tracking.

 ## 2. Architecture Diagram

 ```mermaid
 graph TD
     subgraph "Data Sources (On-Prem / Cloud)"
         A[System/Endpoint Agents] -->|Logs & Metrics| B(AWS MSK / Kafka)
     end
 
     subgraph "Ingestion & Processing Layer"
         B -->|Stream| C{Logstash / Fluentd}
         C -->|Indexing| D[(AWS OpenSearch / SIEM)]
     end
 
     subgraph "AI & Analytics Layer"
         D -->|Query Data| E[AI Analysis Engine]
         E -->|Enrichment| F[Threat Intel / RAG Knowledge Base]
         F -->|Context| E
         E -->|Alert Trigger| G[Alert Manager]
     end
 
     subgraph "SOAR & Response Layer"
         G -->|Trigger| H[AWS Step Functions / SOAR]
         H -->|Action| I[AWS Lambda Remediation]
         H -->|Ticket| J[Jira API]
     end
 
     subgraph "External Ecosystem"
         K(MCP Server - Search) -.->|Ext. Intel| F
         I -.->|Block IP/Disable User| A
     end
 ```

 ## 3. Component Breakdown
 
 ### 3.1 Data Collection & Ingestion
 - **Agents**: `Elastic Agent`, `Filebeat`, or `Metricbeat` deployed on EC2 instances and endpoints to capture system logs (syslog, auth logs), network traffic (Packetbeat), and metrics.
 - **Message Broker**: **AWS MSK (Managed Streaming for Apache Kafka)** ensures decoupling between producers (agents) and consumers (SIEM), providing a persistent buffer for high-volume data streams.
 
 ### 3.2 Storage & Search (SIEM)
 - **Core Engine**: **AWS OpenSearch Service** (successor to ELK on AWS). acts as the central SIEM.
 - **Function**: Indexes massive volumes of log data for sub-second search and visualization via OpenSearch Dashboards.
 
 ### 3.3 AI/ML Analysis Layer
 - **Anomaly Detection**: Unsupervised learning models (Random Cut Forest) running within OpenSearch or AWS SageMaker to detect statistical outliers in network traffic or login patterns.
 - **Threat Enrichment (GenAI)**: 
   - **Service**: AWS Bedrock or self-hosted LLM on SageMaker.
   - **RAG (Retrieval-Augmented Generation)**: Queries a dedicated Knowledge Base (MITRE ATT&CK framework, CVE databases, historical incident logs) to add context to raw alerts.
   - **Analysis**: Explains *why* an anomaly is dangerous and recommends remediation steps.
 
 ### 3.4 Orchestration & Response (SOAR)
 - **Workflow Orchestrator**: **AWS Step Functions** manages the state of an incident response workflow.
 - **Execution Units**: **AWS Lambda** functions (Python/Node.js) to execute specific tasks:
   - Isolate an EC2 instance.
   - Revoke IAM keys.
   - Update firewall/WAF rules.
 
 ### 3.5 Incident Management
 - **Integration**: **Jira REST API**.
 - **Workflow**: When a high-confidence threat is detected, the SOAR layer automatically creates a Jira ticket with:
   - Severity level.
   - Affected assets.
   - AI-generated summary and recommended actions.
 
 ## 4. Data Flow
 1. **Collection**: Agents on target systems ship logs to a Kafka topic in AWS MSK.
 2. **Ingestion**: An ingestion worker (Logstash/Data Prepper) reads from Kafka, normalizes the data (ECS format), and indexes it into AWS OpenSearch.
 3. **Detection**: 
    - Real-time rules match known signatures.
    - Scheduled ML jobs scan for anomalies.
 4. **Analysis**: Upon alert generation, the AI Engine extracts the alert context, queries the Threat Intel Knowledge Base/MCP, and generates a threat narrative.
 5. **Response**: 
    - The alert payload is sent to AWS Step Functions.
    - A Jira ticket is created.
    - If configured for auto-remediation, Lambda functions execute blocking actions.
 
 ## 5. Security Considerations
 - **Data Encryption**: TLS 1.3 for data in transit; AWS KMS for data at rest (MSK, OpenSearch, S3).
 - **Access Control**: IAM Roles and Policies with least-privilege principles. No hardcoded credentials.
 - **Network Isolation**: All components run within a private VPC. Public access is restricted to an Application Load Balancer (ALB) for valid API endpoints only.
 
 ## 6. Assumptions & Limitations
 - **Assumptions**: 
   - User has administrative access to an AWS account.
   - Jira Cloud or Server instance is available for integration.
 - **Limitations**:
   - "Real-time" is subject to ingestion latency (typically <1 minute).
   - Generative AI responses should be reviewed by human analysts before executing destructive actions (e.g., terminating servers).

 ## 7. Future Extensibility
 - **Multi-Cloud Support**: Agents can be deployed on Azure/GCP VMs shipping data to the central AWS hub.
 - **Advanced RAG**: Integrating internal user documentation and policy documents into the RAG store.
 - **ChatOps**: Integration with Slack/Teams for interactive incident response.
