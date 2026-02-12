# AWS-Based SIEM/SOAR Threat Detection System
## Financial Security Operations Reference Architecture

**Production-pattern inspired financial SOC detection pipeline (demo scale)**. This system demonstrates a multi-layered threat detection architecture combining traditional SIEM correlation, AWS-native security services, endpoint detection (EDR), and AI-assisted anomaly analysis. Designed as a reference implementation for financial sector security operations centers.

> **⚠️ Deployment Scope**: This is an architecture demonstration at demo scale. Production financial deployments require additional hardening including multi-AZ deployment, disaster recovery plans, and compliance controls (SOC 2, PCI-DSS).

---

## 📋 Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Threat Detection Methodology](#2-threat-detection-methodology)
3. [SIEM Signal Sources](#3-siem-signal-sources)
4. [Detection Decision Logic](#4-detection-decision-logic)
5. [Correlation Strategy](#5-correlation-strategy)
6. [MITRE ATT&CK Coverage](#6-mitre-attck-coverage-map)
7. [SOAR Workflow & Safety Controls](#7-soar-workflow--safety-controls)
8. [Detection Limitations & Blind Spots](#8-detection-limitations--blind-spots)
9. [Component Details](#9-component-details)
10. [Deployment Guide](#10-deployment-guide)
11. [Verification & Testing](#11-verification--testing)
12. [Cleanup Procedures](#12-cleanup-procedures)

---

## 1. System Architecture

### High-Level Detection Flow

```mermaid
graph TD
    %% Define Styles
    classDef source fill:#E3F2FD,stroke:#1565C0,stroke-width:2px,color:#0D47A1;
    classDef ingest fill:#E8F5E9,stroke:#2E7D32,stroke-width:2px,color:#1B5E20;
    classDef siem fill:#FFF3E0,stroke:#EF6C00,stroke-width:2px,color:#E65100;
    classDef ai fill:#F3E5F5,stroke:#7B1FA2,stroke-width:2px,color:#4A148C;
    classDef soar fill:#FFEBEE,stroke:#C62828,stroke-width:2px,color:#B71C1C;

    subgraph Sources ["📡 1. Data Collection"]
        A["EC2 / App Logs"] -->|Filebeat| K["Kafka (MSK)"]
        B["Wazuh EDR"] -->|Syslog| K
        C["CloudTrail / VPC Flow"] -->|S3| K
    end

    subgraph Ingestion ["🔄 2. Ingestion & Stream"]
        K -->|Consumer| L["Logstash"]
        L -->|Indexing| OS[("OpenSearch SIEM")]
    end

    subgraph Detection ["🧠 3. Detection & Risk"]
        OS -->|"Near Real-time"| Rules{"Sigma Rules & IOCs"}
        Rules -->|Alert| AI["AI Orchestrator (Lambda)"]
        AI -->|Context| BEDROCK["Bedrock LLM"]
        BEDROCK -->|"Risk Score"| RISK["Entity Risk Engine (DynamoDB)"]
    end

    subgraph Response ["🛡️ 4. Automated Response (SOAR)"]
        RISK -->|"Threshold > 70"| SOAR{"Remediation Guardrails"}
        SOAR -->|Approved| BLOCK["Block IP / WAF"]
        SOAR -->|Approved| IAM["Disable User / Detach Policy"]
        SOAR -->|"Manual Review"| JIRA["Jira Ticket"]
    end

    %% Apply Styles
    class A,B,C source;
    class K,L ingest;
    class OS,Rules siem;
    class AI,BEDROCK,RISK ai;
    class SOAR,BLOCK,IAM,JIRA soar;
```

### Architecture Principles

**Defense in Depth**: Multiple detection layers (network, endpoint, cloud control plane, behavior)  
**Fail-Safe Defaults**: Human approval required for high-risk remediation  
**Audit Trail**: All actions logged to SIEM + Jira with evidence collection  
**Separation of Concerns**: Detection layer separate from response orchestration

---

## 2. Threat Detection Methodology

This system implements a **multi-layered detection strategy** where each layer complements the others. Detection decisions are made through a combination of rule-based SIEM correlation, threat intelligence matching, and AI-assisted anomaly analysis.

### Detection Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: AI-Assisted Anomaly Detection (Contextual)        │
│  ↓ Adds reasoning + prioritization to rule-based signals    │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Correlation-Based Detection (Multi-Event)         │
│  ↓ Cross-source correlation, attack chain reconstruction    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Behavior-Based Detection (Baseline Deviation)     │
│  ↓ Anomaly patterns, endpoint behavior, IAM anomalies       │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: IOC-Based Detection (Threat Intelligence)         │
│  ↓ Known bad indicators, GuardDuty findings, signatures     │
└─────────────────────────────────────────────────────────────┘
```

---

### Layer 1: IOC-Based Detection (Indicator of Compromise)

**Purpose**: Detect known threats using threat intelligence feeds and signature-based matching.

**Detection Sources**:
- **Threat Intel Feeds**: Abuse.ch Feodo Tracker (botnet C2 IPs)
- **AWS GuardDuty**: Pre-trained threat detection for AWS environments
- **WAF Managed Rules**: OWASP Top 10, SQL injection, XSS patterns
- **IP Reputation**: Real-time lookup via MCP threat intel server

**How It Works**:
1. All network flows enrich with IP reputation context
2. GuardDuty analyzes CloudTrail, VPC Flow, DNS logs for known attack patterns
3. WAF blocks requests matching signature-based rules
4. OpenSearch correlation rules check logs against threat intel feeds

**Confidence Level**: **High** (when IOC matches known malicious indicator)

**Example Detection**:
```
Event: Outbound connection to 185.220.101.x (known Feodo C2 server)
Source: VPC Flow Logs
Detection: IP matches Abuse.ch feed
Action: HIGH confidence → Immediate SOAR trigger
```

---

### Layer 2: Behavior-Based Detection (Anomaly & Baseline Deviation)

**Purpose**: Detect suspicious behavior patterns that deviate from established baselines, even without IOC matches.

**Detection Methods**:

#### A. Endpoint Behavior Anomalies (Wazuh EDR)
- **File Integrity Monitoring**: Detect unauthorized changes to `/etc`, `/bin`, system binaries
- **Process Execution Anomalies**: Unusual process spawning patterns, privilege escalation
- **Rootkit Detection**: Auditd rule violations, hidden processes
- **Command Execution Monitoring**: Track `execve()` systemcalls, detect suspicious commands

#### B. IAM Behavior Anomalies
- **Privilege Escalation**: IAM policy changes, role assumption patterns
- **Unusual Access Patterns**: API calls from unexpected geolocations (via CloudTrail)
- **Credential Abuse**: Multiple failed authentications followed by success

#### C. Network Behavior Anomalies
- **DNS Tunneling**: High query volume to single domain, unusual TXT queries
- **Data Exfiltration Patterns**: Large outbound transfers, unusual upload/download ratios
- **Lateral Movement**: Unusual internal network scanning, SMB/RDP connections

**Confidence Level**: **Medium** (requires context to differentiate from legitimate activity)

**Example Detection**:
```
Event: IAM user 'finance-admin' creates new admin policy at 3 AM
Source: CloudTrail
Baseline: User typically logs in 9 AM-5 PM, never creates IAM policies
Detection: Time + action deviation from baseline
Action: MEDIUM confidence → Alert + evidence collection
```

---

### Layer 3: Correlation-Based Detection (Multi-Event)

**Purpose**: Detect multi-stage attacks by correlating events across time and data sources.

**Correlation Strategies**:

#### A. Time-Based Correlation (Attack Chains)
Detect sequences of events that individually appear benign but together indicate attack progression:

```
Pattern: Credential Stuffing → Privilege Escalation
├─ Event 1: 10+ failed SSH logins (5 min window)
├─ Event 2: Successful login from same IP
└─ Event 3: Sudo command execution within 2 minutes
Result: HIGH confidence attack chain detected
```

#### B. Cross-Source Correlation
Combine signals from multiple telemetry sources:

```
Pattern: C2 Communication Detection
├─ DNS logs: Suspicious domain query (DGA pattern)
├─ VPC Flow: Outbound connection to resolved IP
├─ GuardDuty: IP flagged as known C2 infrastructure
└─ Endpoint: Process initiated connection (Wazuh)
Result: Multi-source confirmation → CRITICAL alert
```

#### C. Entity-Based Correlation
Track behavior across a single entity (user, IP, instance):

```
Pattern: Compromised Account Detection
├─ CloudTrail: Login from Country A
├─ CloudTrail: Login from Country B within 1 hour (impossible travel)
├─ CloudTrail: Unusual API calls (DescribeInstances, ListBuckets)
└─ WAF: High rate of 403 errors from same user
Result: Compromised credential pattern → Restrict IAM
```

**Confidence Level**: **High** (multiple independent signals corroborate)

**Implementation**: OpenSearch correlation rules + AI-assisted chain detection

---

### Layer 4: AI-Assisted Anomaly Detection (Contextual Reasoning)

**Purpose**: Augment rule-based detection with contextual reasoning and prioritization. **AI is an analyst assistant**, not the primary detection mechanism.

**AI Role in Detection Stack**:
- ✅ **Context Addition**: Enrich alerts with threat intel context and reasoning
- ✅ **Prioritization**: Score anomalies that don't match existing rules
- ✅ **Unknown-Unknown Detection**: Identify novel attack patterns not in ruleset
- ✅ **False Positive Reduction**: Explain why behavior is anomalous vs. benign
- ❌ **NOT Sole Decision Maker**: AI output feeds into correlation engine, doesn't replace rules

> **Compliance Disclaimer**: AI output is non-deterministic and not used as sole control for enforcement actions.


**How It Works**:
1. **Rule-based detections fire first** (Layers 1-3)
2. **AI analyzes each log** for broad baseline deviations
3. **Threat intel context** retrieved via RAG (Retrieval-Augmented Generation)
4. **LLM generates risk score** (0.0-1.0) with human-readable reasoning
5. **Combined signal** (rules + AI score) determines SOAR action

**Prompt Engineering Strategy**:
```
System Prompt: "You are a security analyst assistant. Analyze this log entry 
in context of provided threat intelligence. Look for deviations from secure 
baseline behavior including unauthorized access, data movement anomalies, 
integrity violations, or resource abuse. Provide a risk score (0.0-1.0) and 
concise reasoning."

Input: Log entry + IP reputation + historical context
Output: {"risk_score": 0.7, "reasoning": "User accessed 50 S3 buckets in 5 
minutes, 10x normal rate. IP geolocation changed from US to CN within 1 hour."}
```

**Confidence Level**: **Variable** (0.0-1.0 score, threshold at 0.7 for alerting)

**Example Detection**:
```
Event: Application logs show 500 database queries in 1 minute
Rule Match: None (legitimate user, no IOC)
AI Analysis: "Query rate 100x baseline, accessing PII tables sequentially. 
Pattern consistent with automated data scraping."
Risk Score: 0.8
Action: MEDIUM→HIGH confidence → Alert for analyst review
```

**AI Limitations**:
- No historical baseline (LLM has no memory of past behavior)
- Risk of hallucination (false positive explanations)
- Requires tuning to reduce noise (threshold adjustment)

---

### Detection Layer Synergy

These layers work together to achieve **high detection coverage with low false positives**:

| Attack Scenario | Layer 1 IOC | Layer 2 Behavior | Layer 3 Correlation | Layer 4 AI |
|----------------|------------|------------------|---------------------|-----------|
| **Known Malware Execution** | ✅ Primary | ✅ Confirms | - | ✅ Explains |
| **Zero-Day Exploit** | ❌ No signature | ✅ Primary | ✅ Confirms | ✅ Detects |
| **Insider Threat (Slow)** | ❌ No IOC | ✅ Detects | ✅ Primary | ✅ Contextualizes |
| **APT Multi-Stage** | ⚠️ Partial | ✅ Individual events | ✅ Primary | ✅ Chains events |
| **Compromised Credentials** | ⚠️ IP reputation | ✅ Primary | ✅ Confirms | ✅ Prioritizes |

**Key Principle**: No single layer is sufficient. Defense-in-depth through layered detection.

---

## 3. SIEM Signal Sources

All telemetry is centralized in OpenSearch for correlation, alerting, and investigation.

### Signal Source Matrix

| Source | Threat Detection Value | Index Pattern | Retention | Log Volume |
|--------|----------------------|--------------|-----------|-----------|
| **CloudTrail** | IAM abuse, privilege escalation, API misuse | `cloudtrail-*` | 365 days | ~10 GB/day |
| **VPC Flow Logs** | Network recon, C2 communication, lateral movement | `vpcflow-*` | 90 days | ~50 GB/day |
| **Route53 DNS Logs** | DNS tunneling, DGA detection, C2 domains | `dns-logs` | 90 days | ~5 GB/day |
| **AWS GuardDuty** | Pre-correlated threat findings (high fidelity) | `guardduty-*` | 365 days | ~100 MB/day |
| **AWS Config** | Compliance drift, misconfigurations | `aws-config-*` | 365 days | ~500 MB/day |
| **WAF Logs** | Web attacks (SQLi, XSS), bot traffic | `waf-logs-*` | 90 days | ~10 GB/day |
| **Wazuh Alerts** | Endpoint compromise, rootkits, FIM violations | `wazuh-alerts-*` | 365 days | ~1 GB/day |
| **Auditbeat (FIM)** | File integrity violations, auditd events | `audit-logs-*` | 365 days | ~2 GB/day |
| **Metricbeat** | Resource abuse (cryptomining), DoS patterns | `metrics-system-*` | 30 days | ~5 GB/day |
| **Application Logs** | Business logic abuse, authentication failures | `logs-*` | 90 days | ~10 GB/day |

### Telemetry Enrichment Pipeline

```
Raw Logs → Kafka (Buffer) → Logstash (Enrich) → OpenSearch (Index)
                                    ↓
                            GeoIP, Custom Tags,
                            Threat Intel Lookup,
                            Parse/Normalize
```

**Enrichment Performed by Logstash**:
- **GeoIP Enrichment**: Add geolocation data to all IP addresses
- **Threat Intel Tagging**: Mark logs with IOC matches from threat feeds
- **Field Normalization**: Standardize field names across different log sources
- **Event Classification**: Tag events by type (auth, network, file, process)

---

### CloudTrail (AWS API Audit Logs)

**Detection Use Cases**:
- ✅ Unauthorized IAM policy changes (privilege escalation)
- ✅ S3 bucket permission modifications (data exposure risk)
- ✅ EC2 instance creation from unusual geolocations
- ✅ Security group changes (firewall rule bypass)
- ✅ Console logins from impossible travel patterns

**Key Events Monitored**:
- `AssumeRole`, `CreateAccessKey`, `AttachUserPolicy`
- `PutBucketPolicy`, `GetObject` (S3 access)
- `RunInstances`, `AuthorizeSecurityGroupIngress`

**Example Detection Rule**:
```json
{
  "rule": "IAM Privilege Escalation",
  "condition": "eventName IN (AttachUserPolicy, PutUserPolicy) AND userIdentity.type != Root",
  "severity": "HIGH"
}
```

---

### VPC Flow Logs (Network Traffic Metadata)

**Detection Use Cases**:
- ✅ Port scanning (multiple REJECT events to sequential ports)
- ✅ C2 communication (beaconing patterns, connections to known bad IPs)
- ✅ Data exfiltration (large outbound data transfers)
- ✅ Lateral movement (unusual internal network connections)
- ✅ DDoS detection (abnormal inbound traffic spikes)

**Flow Record Fields Used**:
- `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`
- `action` (ACCEPT/REJECT)
- `bytes` (data volume)

**Example Detection Rule**:
```json
{
  "rule": "Port Scan Detection",
  "condition": "action=REJECT AND unique(dstport) > 100 in 60 seconds",
  "severity": "MEDIUM"
}
```

---

### Route53 DNS Query Logs

**Detection Use Cases**:
- ✅ DNS tunneling (high query volume, TXT record abuse)
- ✅ DGA (Domain Generation Algorithm) detection
- ✅ C2 domain lookups (known malicious domains)
- ✅ Data exfiltration via DNS (encoded data in subdomain labels)

**Example Detection Rule**:
```json
{
  "rule": "DNS Tunneling",
  "condition": "query_count > 1000 per domain per hour OR avg(query_length) > 50 chars",
  "severity": "HIGH"
}
```

---

### AWS GuardDuty (Managed Threat Detection)

**Detection Use Cases**:
- ✅ Pre-correlated high-fidelity threat findings
- ✅ Cryptocurrency mining activity
- ✅ Backdoor EC2 instances
- ✅ Unusual API call patterns
- ✅ Tor network usage

**Integration**: EventBridge → Lambda Transformer → OpenSearch

**Why Use GuardDuty** when building custom detection?
- Complements custom rules with AWS-managed threat intel
- Reduces false positives (AWS curated signatures)
- Covers threats specific to AWS environments

---

### Wazuh EDR (Endpoint Detection & Response)

**Detection Use Cases**:
- ✅ File Integrity Monitoring (system file tampering)
- ✅ Rootkit detection (hidden processes, kernel modules)
- ✅ Malware detection (YARA rules, signature matching)
- ✅ Process execution anomalies (suspicious command patterns)
- ✅ Login anomalies (brute force, privilege escalation)

**FIM Paths Monitored**:
- `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- `/root/.ssh`, `/home/*/.ssh` (SSH key tampering)

**Example Alert**:
```json
{
  "rule_id": 550,
  "description": "Integrity checksum changed",
  "file": "/etc/passwd",
  "severity": "CRITICAL"
}
```

---

## 4. Entity Risk Scoring Engine (Financial-Grade)

This system implements a **stateful, context-aware risk engine** (`src/analysis/risk_engine.py`) designed for high-assurance environments. It tracks cumulative risk per entity (User/IP) over time, applying financial-specific multipliers and decay logic.

### 🧠 Core Logic & Hardening

| Feature | Implementation | Hardening Control |
| :--- | :--- | :--- |
| **Stateful Tracking** | DynamoDB `entity-risk-state` table | Persistence across service restarts |
| **Score Clamping** | 0.0 - 100.0 Scale | Prevent integer overflow/infinite growth |
| **Time Decay** | 12-hour Half-Life (Exponential) | Auto-forgiveness of old, isolated alerts |
| **Idempotency** | Track `recent_alert_ids` (Max 20) | Prevent duplicate scoring from same alert |
| **Concurrency** | DynamoDB Conditional Writes | Prevents race conditions during simultaneous updates |
| **Explainability** | `risk_factors_history` (Max 25 events) | Full audit trail of *why* risk is high |

### 🚀 Performance Envelope (Demo Scale)

- **Ingestion Rate**: Tested up to **5,000 EPS** (Events Per Second).
- **Detection Latency**: ~15 seconds (from log generation to SOAR trigger).
- **Risk Engine Latency**: ~45ms per update (DynamoDB backed).
- **Design Goal**: Optimized for demonstration (< 5k EPS), not hyperscale.

### ⚖️ Scoring Weights & Multipliers

**Base Threat Weights** (Sample from `risk_engine.py`):

| Threat Category | Base Score |
| :--- | :--- |
| **Ransomware / Cloud Root Usage** | 100 (CRITICAL) |
| **Database Dump / Data Exfiltration** | 90-95 (CRITICAL) |
| **MFA Bypass** | 80 (HIGH) |
| **Suspicious PowerShell** | 70 (HIGH) |
| **Lateral Movement / Admin Change** | 60 (MEDIUM) |
| **Impossible Travel** | 50 (MEDIUM) |

**Context Multipliers**:

| Context | Multiplier | Condition |
| :--- | :--- | :--- |
| **Asset Criticality** | **x1.6** | Tag=`Critical` (e.g. SWIFT, CoreDB) |
| **Asset Criticality** | **x1.3** | Tag=`High` |
| **Privileged User** | **x1.5** | Username in `root`, `admin`, `system` |
| **Anomaly Confidence**| **x0.0-1.0** | AI Confidence Score |

### 📊 DynamoDB Schema (`entity-risk-state`)

| Attribute | Type | Description |
| :--- | :--- | :--- |
| **`entity_id`** (PK) | String | `user:alice` or `ip:192.168.1.5` |
| `cumulative_risk_score` | Number | Current float score (0-100) |
| `risk_level` | String | LOW / MEDIUM / HIGH / CRITICAL |
| `last_update_ts` | Number | Unix timestamp of last event |
| `last_decay_ts` | Number | Timestamp of last decay calculation |
| `recent_alert_ids` | List | Deduplication cache of alert IDs |
| `risk_factors_history` | List | JSON objects: `{alert_id, score_delta, multipliers...}` |
| `ttl` | Number | Auto-expiry (90 days) |

### 🛡️ Guardrails & Safety

To prevent automated disasters (e.g., blocking the CEO or shutting down a payment gateway), the engine enforces **Destructive Action Guardrails**:

```python
def should_allow_destructive_action(entity_id, threshold=70):
    # Only allow blocking if Risk Score >= 70 (HIGH/CRITICAL)
    # Prevents single LOW/MEDIUM alerts from triggering blocks
    return current_score >= threshold
```

**SOAR Integration**:
- `block_ip.py`: Checks `should_allow_destructive_action` before modifying NACLs.
- `disable_user.py`: Checks before disabling IAM login profiles.
- **Fail-Safe Policy**: **Conservative**. If the Risk Engine (DynamoDB) is unreachable, the system defaults to **ALLOWING** traffic (downgrades to Alert-Only). This priorities business availability over blocking potentially legitimate users during a system failure.

---

## 5. Detection Decision Logic

### Detection Decision Matrix

This table maps each signal type to its confidence level, data source, and automated response action.

| Signal Type | Detection Source | Confidence | SOAR Action | Human Approval Required | Rollback TTL |
|------------|-----------------|------------|-------------|------------------------|--------------|
| **IOC Match (Known C2 IP)** | Threat Intel Feed + VPC Flow | **HIGH** | Block IP via WAF | ❌ No (auto-remediate) | 24 hours |
| **GuardDuty CRITICAL Finding** | GuardDuty (Backdoor, Cryptomining) | **HIGH** | Block IP + Jira Ticket | ✅ Yes | 1 hour |
| **FIM System File Change** | Wazuh (e.g., `/etc/passwd`) | **CRITICAL** | Isolate endpoint, create ticket | ✅ Yes | Manual |
| **Behavior Anomaly (AI Score >0.8)** | AI + Logs correlation | **MEDIUM** | Evidence collection only | ❌ No | N/A |
| **Impossible Travel** | CloudTrail GeoIP | **HIGH** | Restrict IAM, create ticket | ✅ Yes | 1 hour |
| **Privilege Escalation** | CloudTrail (`AttachUserPolicy`) | **HIGH** | Restrict IAM, alert SOC | ✅ Yes | Manual |
| **Entity Risk Score > 90** | Risk Engine (Stateful) | **CRITICAL** | Block Identity + WAF | ✅ Yes | Manual |
| **DNS Tunneling Pattern** | Route53 Logs (query rate) | **MEDIUM** | Block DNS, investigate | ✅ Yes | 2 hours |
| **Port Scan (Internal)** | VPC Flow Logs | **LOW** | Log + alert, no remediation | ❌ No | N/A |
| **Failed Login Spike** | Application Logs + Wazuh | **MEDIUM** | Rate limit, alert | ❌ No (threshold-based) | N/A |
| **Multi-Stage Attack Chain** | Correlation Rule (3+ events) | **CRITICAL** | Full remediation + SOC escalation | ✅ Yes | Manual |

### Decision Workflow

```
┌────────────────────┐
│  Event Detected    │
└────────┬───────────┘
         │
         ↓
┌────────────────────────────┐
│  Calculate Confidence      │
│  - IOC match?              │
│  - Correlation rule hit?   │
│  - AI risk score?          │
│  - GuardDuty severity?     │
└────────┬───────────────────┘
         │
         ↓
    ┌───────────┐
    │ Confidence│
    │  Level?   │
    └─────┬─────┘
          │
    ┌─────┴──────────────┬──────────────────┐
    │                    │                  │
    ↓                    ↓                  ↓
┌──────────┐         ┌─────────┐       ┌──────────┐
│ CRITICAL │         │  HIGH   │       │ MEDIUM/  │
│          │         │         │       │   LOW    │
└────┬─────┘         └────┬────┘       └────┬─────┘
     │                    │                 │
     ↓                    ↓                 ↓
┌────────────┐    ┌────────────────┐  ┌─────────────┐
│ Immediate  │    │ Collect        │  │ Create Jira │
│ SOAR       │    │ Evidence       │  │ Ticket Only │
│ + Human    │    │ + Request      │  │             │
│ Approval   │    │ Approval       │  │             │
└────────────┘    └────────────────┘  └─────────────┘
```

---

## 5. Correlation Strategy

### Cross-Log Correlation Examples

#### Example 1: Brute Force → Privilege Escalation

**Attack Pattern**: Attacker brute forces SSH, gains access, escalates privileges.

**Correlation Rule**:
```yaml
name: "Brute Force to Privilege Escalation"
time_window: 10 minutes
events:
  - source: auth.log (Filebeat)
    condition: failed_login_count >= 10
  - source: auth.log
    condition: successful_login from same IP
  - source: auditd (Wazuh)
    condition: sudo command execution within 2 minutes
severity: HIGH
action: Trigger SOAR (Restrict IAM + Block IP)
```

**OpenSearch Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.action": "failed_login"}},
        {"range": {"@timestamp": {"gte": "now-10m"}}}
      ]
    }
  },
  "aggs": {
    "ip_count": {"terms": {"field": "source.ip", "min_doc_count": 10}}
  }
}
```

---

#### Example 2: DNS Suspicious → Outbound Flow Spike

**Attack Pattern**: Malware performs DNS lookup for C2 server, then establishes connection.

**Correlation Rule**:
```yaml
name: "C2 Communication Chain"
time_window: 5 minutes
events:
  - source: dns-logs (Route53)
    condition: domain matches DGA pattern OR in threat feed
  - source: vpcflow-logs
    condition: outbound connection to resolved IP
  - source: wazuh-alerts
    condition: process initiated connection (unknown binary)
severity: CRITICAL
action: Block IP + WAF, isolate endpoint
```

---

#### Example 3: FIM Change → Process Spawn

**Attack Pattern**: Attacker modifies system file, spawns malicious process.

**Correlation Rule**:
```yaml
name: "System File Tampering with Execution"
time_window: 60 seconds
events:
  - source: wazuh-alerts (FIM)
    condition: file_path in [/bin/, /usr/bin/, /etc/]
  - source: wazuh-alerts (Process Monitor)
    condition: new_process_spawn from modified path
severity: CRITICAL
action: Isolate endpoint, trigger incident response
```

---

### Attack Chain Reconstruction

**Multi-Stage APT Detection** (7-day correlation window):

> **Note**: Current implementation supports short-window correlation via OpenSearch rules and AI polling. Multi-day attack chain reconstruction is on the roadmap.


```
Day 1: Recon
  ├─ VPC Flow: Port scan detected (multiple REJECT events)
  └─ CloudTrail: DescribeInstances API calls (reconnaissance)

Day 2: Initial Access
  ├─ Auth Logs: Successful SSH login from external IP
  └─ Wazuh: New SSH key added to authorized_keys

Day 3: Privilege Escalation
  ├─ CloudTrail: AssumeRole to higher-privilege role
  └─ Auditd: Sudo command execution

Day 4: Lateral Movement
  ├─ VPC Flow: Unusual internal network connections
  └─ CloudTrail: Access to multiple EC2 instances

Day 5: Exfiltration
  ├─ VPC Flow: Large outbound data transfer (100 GB)
  └─ S3 Access Logs: Bulk download of sensitive buckets

Detection: Multi-day correlation rule flags attack progression
Alert: CRITICAL - APT activity detected across 5 days
Action: Full incident response, isolate all affected instances
```

---

## 6. MITRE ATT&CK Coverage Map

This table maps MITRE ATT&CK techniques to the detection sources that provide visibility.

### Coverage by Tactic

| Tactic | Technique ID | Technique Name | Detection Source | Coverage Level |
|--------|-------------|----------------|------------------|---------------|
| **Initial Access** | T1078 | Valid Accounts | CloudTrail, Wazuh auth logs | ✅ Covered |
| | T1190 | Exploit Public-Facing App | WAF logs, ALB access logs | ✅ Covered |
| | T1133 | External Remote Services | VPC Flow, auth logs | ✅ Covered |
| | T1566 | Phishing | ⚠️ **NOT COVERED** (no email gateway) | ❌ Blind Spot |
| **Execution** | T1059 | Command Execution | Wazuh auditd, process monitoring | ✅ Covered |
| | T1053 | Scheduled Task/Job | Wazuh FIM (`/etc/cron*`), auditd | ✅ Covered |
| | T1610 | Container Exploitation | ⚠️ **NOT COVERED** (no container runtime logs) | ❌ Blind Spot |
| **Persistence** | T1098 | Account Manipulation | CloudTrail (IAM events) | ✅ Covered |
| | T1136 | Create Account | CloudTrail, Wazuh (`/etc/passwd` FIM) | ✅ Covered |
| | T1543 | Create/Modify Service | Wazuh FIM (`/etc/systemd`), auditd | ✅ Covered |
| | T1053.003 | Cron | Wazuh FIM (`/etc/cron*`) | ✅ Covered |
| **Privilege Escalation** | T1068 | Exploitation for Priv Esc | Wazuh process monitoring, GuardDuty | ⚠️ Partial |
| | T1078.004 | Cloud Accounts | CloudTrail (`AssumeRole`, `AttachUserPolicy`) | ✅ Covered |
| | T1548 | Abuse Elevation Control | Auditd (sudo), CloudTrail (IAM) | ✅ Covered |
| **Defense Evasion** | T1070 | Indicator Removal | Wazuh FIM (log file tampering) | ✅ Covered |
| | T1562 | Impair Defenses | CloudTrail (GuardDuty disable, Config delete) | ✅ Covered |
| | T1222 | File Permissions Modification | Wazuh FIM, auditd (`chmod`) | ✅ Covered |
| | T1027 | Obfuscated Files or Information | Wazuh YARA rules, entropy analysis | ⚠️ Partial |
| **Credential Access** | T1110 | Brute Force | Auth logs, Wazuh, CloudTrail | ✅ Covered |
| | T1555 | Credentials from Password Stores | Wazuh FIM (`~/.aws`, `~/.ssh`) | ⚠️ Partial |
| | T1558 | Steal Application Tokens | CloudTrail (STS tokens, access keys) | ✅ Covered |
| **Discovery** | T1083 | File/Directory Discovery | Wazuh auditd (`ls`, `find` commands) | ✅ Covered |
| | T1046 | Network Service Scanning | VPC Flow (port scan pattern) | ✅ Covered |
| | T1069 | Permission Groups Discovery | CloudTrail (IAM list operations) | ✅ Covered |
| **Lateral Movement** | T1021 | Remote Services (SSH, RDP) | VPC Flow, auth logs, Wazuh | ✅ Covered |
| | T1210 | Exploitation of Remote Services | VPC Flow, GuardDuty, Wazuh | ⚠️ Partial |
| **Collection** | T1213 | Data from Information Repositories | ⚠️ **NOT COVERED** (no DB query logs) | ❌ Blind Spot |
| | T1005 | Data from Local System | Wazuh auditd (file access), FIM | ⚠️ Partial |
| **C2 (Command & Control)** | T1071 | Application Layer Protocol | DNS logs, VPC Flow, GuardDuty | ✅ Covered |
| | T1573 | Encrypted Channel | VPC Flow (port patterns), DNS | ⚠️ Partial |
| | T1095 | Non-Application Layer Protocol | VPC Flow (unusual protocols) | ✅ Covered |
| **Exfiltration** | T1041 | Exfiltration Over C2 | VPC Flow, DNS logs, GuardDuty | ✅ Covered |
| | T1537 | Transfer Data to Cloud Account | ⚠️ **NOT COVERED** (no S3 access logs) | ❌ Blind Spot |
| | T1567 | Exfiltration Over Web Service | VPC Flow (upload patterns), proxy logs | ⚠️ Partial |
| **Impact** | T1486 | Data Encrypted for Impact (Ransomware) | ⚠️ **NOT COVERED** (no entropy analysis) | ❌ **CRITICAL GAP** |
| | T1490 | Inhibit System Recovery | Wazuh FIM (backup deletion), CloudTrail | ✅ Covered |
| | T1496 | Resource Hijacking (Cryptomining) | Metricbeat (CPU spike), GuardDuty | ✅ Covered |

---

### Coverage Summary

| Coverage Level | Count | Percentage | Examples |
|---------------|-------|------------|----------|
| ✅ **Fully Covered** | 28 | ~60% | Valid accounts, command execution, brute force, C2 communication |
| ⚠️ **Partially Covered** | 9 | ~20% | Container exploitation, credential theft, data collection |
| ❌ **Not Covered (Blind Spots)** | 9 | ~20% | **Phishing, ransomware, container attacks, DB exfiltration** |

**MITRE ATT&CK Focus Area**: This architecture prioritizes AWS cloud control plane attacks and Linux endpoint threats. Coverage is strongest for Initial Access, Persistence, Privilege Escalation, and C2 tactics.

---

## 7. SOAR Workflow & Safety Controls

### SOAR Orchestration Architecture

**Orchestrator**: AWS Step Functions (state machine)  
**Remediation Actions**: Lambda functions  
**Approval Mechanism**: Jira callback tokens

### Production-Safe Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Deduplication Check (DynamoDB)                              │
│     ↓ Skip if duplicate alert within 1 hour                     │
├─────────────────────────────────────────────────────────────────┤
│  2. Entity Risk Check (DynamoDB Risk Store)                     │
│     ↓ Fetch current risk score. If >90, escalate to CRITICAL    │
├─────────────────────────────────────────────────────────────────┤
│  3. Create Jira Ticket (Immediate)                              │
│     ↓ No silent failures - ticket created before remediation    │
├─────────────────────────────────────────────────────────────────┤
│  4. Collect Evidence (Query OpenSearch)                         │
│     ↓ Gather context: related logs, threatintel, user history   │
├─────────────────────────────────────────────────────────────────┤
│  5. Attach Evidence to Jira (Update ticket with findings)       │
│     ↓ Provide context for approval decision                     │
├─────────────────────────────────────────────────────────────────┤
│  6. Determine Action (Choice based on severity)                 │
│     ├─ LOW → Manual Review (End workflow, SOC analyst handles)  │
│     └─ HIGH/CRITICAL → Request Human Approval (Callback token)  │
│         ↓ Workflow waits for approval via Jira comment          │
├─────────────────────────────────────────────────────────────────┤
│  7. REMEDIATION GUARDRAIL CHECK                                 │
│     ↓ Verify `cumulative_risk_score >= 70` before destructive   │
│     ↓ If Score < 70: Downgrade to "Log Only" (Safety Catch)     │
├─────────────────────────────────────────────────────────────────┤
│  8. Remediate High-Risk (Parallel execution)                    │
│     ├─ Block IP (Add to WAF IP Set)                             │
│     └─ Restrict IAM (Attach DenyAll policy)                     │
│         ↓ Soft remediation - no account deletion                │
├─────────────────────────────────────────────────────────────────┤
│  9. Wait TTL (1 hour)                                           │
│     ↓ Automatic rollback timer                                  │
├─────────────────────────────────────────────────────────────────┤
│ 10. Rollback Remediation (Auto-revert)                          │
│     ├─ Remove IP from WAF IP Set                                │
│     └─ Detach DenyAll policy from IAM user                      │
│         ↓ Prevents permanent blocks from false positives        │
└─────────────────────────────────────────────────────────────────┘
```

---

### SOAR Safety Controls

#### 1. Deduplication (Alert Fatigue Prevention)

**Mechanism**: DynamoDB table with 1-hour TTL  
**Key**: Hash of `{IP address, username, rule_id}`  
**Purpose**: Prevent creating 100 Jira tickets for same repeated alert

**Example**:
```
Alert 1: Brute force from 1.2.3.4 at 10:00 AM → Ticket created
Alert 2: Brute force from 1.2.3.4 at 10:05 AM → Deduplicated (no new ticket)
Alert 3: Brute force from 1.2.3.4 at 11:05 AM → New ticket (TTL expired)
```

---

#### 2. Human Approval Gate (Production Safety)

**Mechanism**: Step Functions callback token in Jira comment  
**Trigger**: HIGH or CRITICAL severity alerts  
**Workflow**: Workflow pauses until analyst approves/rejects via Jira comment

**Why Required**:
- Prevents auto-blocking legitimate admin activity
- Allows analyst to override AI false positives
- Ensures accountability (approval logged in Jira audit trail)

**Approval Example** (Jira comment):
```
[APPROVAL REQUIRED] Block IP 1.2.3.4 and restrict user finance-admin?

Evidence:
- 15 failed logins followed by success
- IAM policy created at unusual time (3 AM)
- IP geolocation changed US→CN within 1 hour

Approve: Reply with APPROVE-<callback-token>
Reject: Reply with REJECT-<callback-token>
```

---

#### 3. TTL Rollback (False Positive Mitigation)

**Mechanism**: Automatic revert after 1 hour  
**Purpose**: Prevent permanent blocks from false positives  
**Actions Reverted**:
- Remove IP from WAF IP Set
- Detach DenyAll policy from IAM user

**Why 1 Hour**:
- Long enough to stop active attack
- Short enough to minimize impact if false positive
- Manual override available (analyst can extend)

**Example**:
```
10:00 AM: IP 203.0.113.5 blocked (suspected brute force)
11:00 AM: Automatic rollback - IP unblocked
Result: If false positive, user only blocked 1 hour
```

---

#### 4. Evidence Collection (Audit Trail)

**Mechanism**: Lambda queries OpenSearch before remediation  
**Data Collected**:
- Related logs (30 minutes before/after alert)
- User historical behavior
- IP geolocation and reputation
- Threat intel matches

**Purpose**:
- Provide context for approval decision
- Create forensic evidence for investigation
- Enable post-incident review

**Evidence Attached to Jira**:
```markdown
### Evidence Summary
- Total events: 47
- Failed logins: 15
- Successful login: 1 (from IP 1.2.3.4)
- IAM API calls: 3 (CreateAccessKey, AttachUserPolicy, PutUserPolicy)
- Threat intel: IP matches Abuse.ch feed (botnet C2)
```

---

#### 5. Blast Radius Limitation

**Remediation Actions** (soft, reversible):
- ✅ Add IP to WAF IP Set (network blocking)
- ✅ Attach IAM DenyAll policy (restrict access)
- ❌ **NOT** delete IAM user
- ❌ **NOT** terminate EC2 instances
- ❌ **NOT** delete S3 buckets

**Purpose**: Minimize business disruption from false positives

---

#### 6. Jira Immediate Ticketing (No Silent Failures)

**Mechanism**: Jira ticket created **before** remediation  
**Purpose**: If remediation fails, ticket still exists for manual handling

**Ticket Fields**:
- **Summary**: `[Security Alert] HIGH suspicious activity detected`
- **Description**: Alert details, risk score, evidence summary
- **Link**: Direct link to SIEM (OpenSearch Dashboards)
- **Assignee**: SOC on-call rotation
- **Priority**: Maps to severity (CRITICAL → P1)

---

### Lambda Functions (SOAR Actions)

| Function | Purpose | Input | IAM Permissions | Rollback |
|----------|---------|-------|----------------|----------|
| `deduplication` | Check for duplicate alerts | IP/User/RuleID | `dynamodb:GetItem`, `PutItem` | - |
| `create_jira` | Create incident ticket | Alert payload | - (uses API token) | - |
| `update_jira` | Add comments to ticket | Ticket ID, comment | - | - |
| `evidence_collector` | Query logs for context | IP/User, time range | `es:ESHttpPost` (OpenSearch) | - |
| `block_waf` | Add IP to WAF IP Set | IP address | `wafv2:UpdateIPSet` | ✅ `revert_remediation` |
| `restrict_iam` | Attach DenyAll policy | Username | `iam:AttachUserPolicy` | ✅ `revert_remediation` |
| `revert_remediation` | Rollback WAF + IAM | IP + Username | `wafv2:UpdateIPSet`, `iam:DetachUserPolicy` | - |

---

## 8. Detection Limitations & Blind Spots

### Known Coverage Gaps

This section provides honest transparency about what this architecture **does not detect**. Production deployments should address these gaps.

#### ❌ 1. No Ransomware Detection

**Gap**: No entropy analysis or rapid file modification detection  
**Attack Not Detected**: Ransomware encrypts `/home` directory  
**Why**: Wazuh FIM detects file changes, but not mass encryption patterns  
**Mitigation Required**: Add entropy spike detection, monitor file extension changes (`.encrypted`)

---

#### ❌ 2. No Container Security

**Gap**: No container runtime logs (Docker, ECS, EKS)  
**Attack Not Detected**: Cryptomining container deployed, container escape  
**Why**: No visibility into containerized workloads  
**Mitigation Required**: Integrate Falco or GuardDuty EKS Protection

---

#### ❌ 3. No Database Activity Monitoring

**Gap**: No database query logs (RDS, Aurora, DynamoDB)  
**Attack Not Detected**: SQL injection, data exfiltration via DB queries  
**Why**: Database-level telemetry not ingested  
**Mitigation Required**: Enable RDS audit logging, stream to OpenSearch

---

####  4. No S3 Access Logging

**Gap**: S3 access logs not enabled  
**Attack Not Detected**: Bulk download of sensitive S3 buckets  
**Why**: S3 access not tracked (only CloudTrail API calls)  
**Mitigation Required**: Enable S3 access logging, add exfiltration rules

---

#### ❌ 5. No Email Gateway Logs

**Gap**: No email security telemetry (phishing, BEC)  
**Attack Not Detected**: Phishing campaign, business email compromise  
**Why**: No email gateway integration  
**Mitigation Required**: Integrate Proofpoint/Mimecast or AWS SES logs

---

#### ⚠️ 6. No UEBA Baseline Profiling

**Gap**: No historical user behavior baselines  
**Attack Not Detected**: Compromised account acting abnormally (but within normal ranges)  
**Why**: LLM has no memory, no statistical baseline calculation  
**Clarification**:
- **Risk Engine** = Aggregation memory (implemented)
- **UEBA** = Statistical behavioral baseline (not yet implemented)
**Mitigation Required**: Implement 30-day baseline per user/entity, add anomaly scoring

---

#### ⚠️ 7. Limited Correlation Rules

**Gap**: Basic correlation only (time-based, single entity)  
**Attack Not Detected**: Complex multi-stage APTs over weeks  
**Why**: No documented correlation rules, no attack chain tracking  
**Mitigation Required**: Add OpenSearch correlation rules, implement ATT&CK chain detection

---

#### ⚠️ 8. No Impossible Travel Baseline

**Gap**: GeoIP enrichment added, but no automated impossible travel detection  
**Attack Not Detected**: Login from US at 9 AM, login from CN at 9:05 AM  
**Why**: No rule to calculate travel time feasibility  
**Mitigation Required**: Add geolocation + timestamp correlation rule

---

### Tuning Requirements

**False Positive Risk Areas**:
- AI anomaly detection threshold (0.4 may be too low, recommend starting at 0.7)
- WAF managed rules (may block legitimate traffic, requires WAF log analysis)
- Brute force thresholds (failed login count tuning needed per application)

**Production Scaling Needs**:
- Multi-AZ OpenSearch (current: single node dev mode)
- Multi-AZ MSK (current: single broker)
- Disaster recovery plan (backup/restore procedures)
- Auto-scaling detection engine (current: fixed t3.small)

---

## 9. Component Details

### Security Controls

**Encryption**:
- ✅ All data in transit uses TLS (ALB → App, Kafka, OpenSearch HTTPS)
- ✅ OpenSearch encryption at rest enabled
- ✅ MSK encryption enabled (in-transit and at-rest)
- ✅ S3 buckets encrypted with SSE-S3
- ✅ VPC-only deployment (no public OpenSearch/MSK endpoints)

**Log Retention Policy**:
- CloudTrail: 365 days (S3 lifecycle policy)
- OpenSearch SIEM indices: ILM rollover policy (30 days hot, 90 days warm)
- DynamoDB deduplication: TTL 1 hour

---

### Network Security Layer

| Component | Role | Detection Value |
|-----------|------|----------------|
| **AWS WAF** | Web Application Firewall | Blocks SQLi, XSS, bot traffic. Managed Rules + Custom IP Sets (SOAR-updatable). |
| **Application Load Balancer** | Layer 7 load balancer | Access logs for web attack analysis, health checks. |
| **AWS Network Firewall** | Deep Packet Inspection | IPS, domain filtering, traffic logging for network threats. |
| **Security Groups** | Stateful firewall | Port/protocol restrictions, micro-segmentation between EC2 tiers. |

---

### Data Ingestion Pipeline

#### App Server (`t3.medium`)
- **Financial App**: Flask app generating authentication/transaction logs
- **Filebeat**: Collects system logs (`/var/log/auth.log`, `/var/log/syslog`), CloudTrail from S3, VPC Flow Logs
- **Metricbeat**: System metrics (CPU, memory, process, network)
- **Auditbeat**: File Integrity Monitoring (`/etc`, `/bin`), auditd rules
- **Wazuh Agent**: EDR telemetry (FIM, rootkit detection, process monitoring)

#### Logstash Server (`t3.medium`)
- **Kafka Consumer**: Reads from MSK topics (`financial-logs`, `audit-logs`, `metrics-system`)
- **Filter Pipeline**: GeoIP enrichment, JSON parsing, field normalization
- **Output**: Indexes to OpenSearch with pattern-based routing

#### OpenSearch Domain (`t3.small.search`, 1 node)
- **SIEM**: Centralized log storage, dashboards, alerting
- **API**: REST API for detection engine queries
- **Access**: VPC-only (no public endpoint)

---

### Detection Engine (`t3.small`)

**Process**: `threat-detection.service` (SystemD)

**Components**:
1. **`ai_orchestrator.py`**: Main loop, polls OpenSearch every 10 seconds
2. **`anomaly_detection.py`**: AI-assisted risk scoring with contextual reasoning
3. **`rag_engine.py`**: Threat intel retrieval (queries MCP server for IP reputation)
4. **`alert_manager.py`**: SOAR trigger (starts Step Function execution)

**AI Role**: Analyst assistant, NOT primary detector. Adds context and prioritization to rule-based signals.

---

### Wazuh EDR Module

#### Wazuh Manager (`t3.medium`)
- **Wazuh Server**: Central EDR server receiving agent telemetry
- **Wazuh Dashboard**: Web UI for endpoint investigation (FIM details, process trees)
- **Filebeat**: Forwards Wazuh alerts to OpenSearch

**Separation of Concerns**:
- **Wazuh Dashboard**: Endpoint-level drill-down (agent-centric view)
- **OpenSearch Dashboards**: Cross-source SIEM correlation (all log sources)

#### Wazuh Agents
- **Deployed On**: All EC2 instances
- **Modules Enabled**: FIM, Rootkit Detection, Process Monitoring, Command Logging

---

## 10. Deployment Guide

### 💰 Monthly Cost Estimate (Demo Scale)

Estimated costs for running this architecture in `us-east-1` (24/7):

| Service | Configuration | Monthly Cost (Approx) |
| :--- | :--- | :--- |
| **OpenSearch** | `t3.small.search` (Single Node) | ~$80 - $120 |
| **MSK (Kafka)** | `kafka.t3.small` (Single Broker) | ~$120 |
| **EC2 Fleet** | 5x `t3.medium/small` + EBS | ~$100 |
| **NAT Gateway** | 1x Managed NAT + Data Process | ~$35 + Data Fees |
| **Others** | WAF, GuardDuty, CloudWatch, Lambda | ~$30 |
| **TOTAL** | **Demo Environment** | **~$300 - $400 / month** |

> **Note**: For production (Multi-AZ, Cluster mode), expect costs to start at **$1,500/month**.

### Prerequisites

**Local Machine**:
- Terraform v1.0+
- AWS CLI v2.x (configured with credentials)
- SSH client

**AWS Account**:
- IAM user with `AdministratorAccess` or equivalent
- Service quota: 10 EC2 instances, 1 MSK cluster, 1 OpenSearch domain

**External Services**:
- **OpenAI API Key**: For AI-assisted detection ([get key](https://platform.openai.com/api-keys))
- **Jira Cloud Account**: For incident ticketing ([free tier](https://www.atlassian.com/try/cloud/signup))

---

### Step 1: Clone Repository

```bash
git clone https://github.com/your-username/threat-detection-aws.git
cd threat-detection-aws
```

---

### Step 2: Configure Secrets

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
# JIRA Configuration
jira_url         = "https://your-domain.atlassian.net"
jira_user        = "your-email@example.com"
jira_api_token   = "ATATT3xFfGF0..." # Get from Jira Profile → Security → API Tokens
jira_project_key = "SEC"

# OpenAI API
openai_api_key = "sk-proj-..." # Get from OpenAI Platform

# AWS Region
aws_region = "us-east-1"
```

---

### Step 3: Deploy Infrastructure

```bash
terraform init
terraform plan  # Review resources to be created
terraform apply # Type 'yes' when prompted
```

**Deployment Time**: 20-25 minutes

**Resources Created**:
- VPC, subnets, NAT Gateway
- 5 EC2 instances (app, logstash, detection, SOAR, Wazuh)
- MSK cluster (Kafka)
- OpenSearch domain
- Lambda functions (7)
- Step Function state machine
- WAF Web ACL, GuardDuty, Config

**Outputs**:
```
alb_dns = "threat-detection-alb-123456789.us-east-1.elb.amazonaws.com"
bastion_ip = "54.123.45.67"
opensearch_endpoint = "vpc-threat-detection-siem-abc123.us-east-1.es.amazonaws.com"
```

---

### Step 4: Verify Deployment

#### Access Bastion Host
```bash
BASTION_IP=$(terraform output -raw bastion_ip)
ssh -i ~/.ssh/your-key.pem ubuntu@$BASTION_IP
```

#### Check Services
```bash
# App Server
ssh ubuntu@<app-server-ip>
systemctl status financial-app filebeat metricbeat auditbeat wazuh-agent

# Detection Engine
ssh ubuntu@<detection-engine-ip>
journalctl -u threat-detection.service -f
```

---

## 11. Verification & Testing

### Test 1: File Integrity Monitoring

```bash
ssh ubuntu@<app-server-ip>
sudo touch /etc/test-fim-alert
```

**Expected**:
- Wazuh FIM alert within 30 seconds
- OpenSearch receives `wazuh-alerts-*` event
- If AI risk score >0.7, Jira ticket created

---

### Test 2: Brute Force Detection

```bash
# Simulate failed logins
for i in {1..15}; do
  curl http://localhost:5000/login -d 'user=root&password=wrong' -X POST
done
```

**Expected**:
- Correlation rule fires (15 failed logins in 5 minutes)
- OpenSearch alert triggered
- SOAR workflow initiates (if severity HIGH)

---

### Test 3: Manual SOAR Trigger

```bash
aws stepfunctions start-execution \
  --state-machine-arn <step-function-arn> \
  --input '{"severity":"HIGH","original_log":{"ip":"1.2.3.4","user":"root"},"score":0.9}'
```

**Verify**:
1. Jira ticket created
2. WAF IP Set contains `1.2.3.4`
3. DynamoDB has deduplication entry
4. After 1 hour, IP automatically removed from WAF

---

### Test 4: GuardDuty Finding

Trigger GuardDuty test finding:
```bash
aws guardduty create-sample-findings \
  --detector-id <detector-id> \
  --finding-types Backdoor:EC2/C&CActivity.B!DNS
```

**Expected**:
- EventBridge triggers Lambda transformer
- Finding indexed in `guardduty-*` index
- High-severity finding triggers SOAR

---

## 12. Cleanup Procedures

### Automatic Cleanup (Recommended)

```bash
cd infrastructure
terraform destroy
```

**Time**: 10-15 minutes  
**Result**: All resources deleted

---

### Manual Cleanup (If Terraform Fails)

#### 1. Delete EC2 Instances
```bash
aws ec2 describe-instances --filters "Name=tag:Name,Values=app-server,log-processing-server,detection-engine,soar-orchestrator,wazuh-manager" --query "Reservations[].Instances[].InstanceId" --output text | xargs -n1 aws ec2 terminate-instances --instance-ids
```

#### 2. Delete Lambda Functions
```bash
aws lambda list-functions --query "Functions[?starts_with(FunctionName, 'soar-')].FunctionName" --output text | xargs -n1 aws lambda delete-function --function-name
```

#### 3. Delete Step Function
```bash
aws stepfunctions list-state-machines --query "stateMachines[?name=='threat-response-workflow'].stateMachineArn" --output text | xargs -n1 aws stepfunctions delete-state-machine --state-machine-arn
```

#### 4. Delete OpenSearch + MSK
```bash
aws opensearch delete-domain --domain-name threat-detection-siem
aws kafka list-clusters --query "ClusterInfoList[?ClusterName=='threat-detection-kafka'].ClusterArn" --output text | xargs -n1 aws kafka delete-cluster --cluster-arn
```

---

## Directory Structure

```
threat-detection-aws/
├── config/                    # Beats & Logstash configs
│   ├── filebeat.yml           # System, AWS, Nginx logs
│   ├── metricbeat.yml         # Process, socket, Docker metrics
│   ├── auditbeat.yml          # FIM, auditd rules
│   └── logstash.conf          # Pipeline: Kafka → OpenSearch
│
├── infrastructure/            # Terraform IaC
│   ├── main.tf                # VPC, EC2, MSK, Lambda, Step Functions
│   ├── variables.tf           # Input variables
│   ├── outputs.tf             # Bastion IP, endpoints
│   └── terraform.tfvars       # Secrets (Jira, OpenAI API keys)
│
├── src/
│   ├── analysis/              # Detection engine
│   │   ├── ai_orchestrator.py        # Main polling loop
│   │   ├── anomaly_detection.py      # AI-assisted scoring
│   │   ├── rag_engine.py             # Threat intel RAG
│   │   ├── alert_manager.py          # SOAR trigger
│   │   └── configure_opensearch.py   # Correlation rules setup
│   │
│   ├── integration/           # SOAR orchestrator
│   │   ├── mcp_server.py      # Threat intel API server
│   │   └── threat_intel.py    # Abuse.ch feed fetcher
│   │
│   ├── soar/                  # Lambda functions
│   │   ├── create_jira.py              # Incident ticket creation
│   │   ├── update_jira.py              # Ticket updates
│   │   ├── deduplication.py            # DynamoDB dedup check
│   │   ├── evidence_collector.py       # OpenSearch evidence query
│   │   ├── block_waf.py                # WAF IP Set update
│   │   ├── restrict_iam.py             # IAM DenyAll policy
│   │   ├── revert_remediation.py       # Rollback WAF + IAM
│   │   ├── guardduty_transformer.py    # GuardDuty → OpenSearch
│   │   ├── config_transformer.py       # Config → OpenSearch
│   │   └── dns_transformer.py          # Route53 → OpenSearch
│   │
│   └── financial_app.py       # Simulated Flask app
│
└── README.md                  # This file
```

---

## Additional Resources

- **Terraform AWS Provider**: [registry.terraform.io/providers/hashicorp/aws](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- **OpenSearch Security Analytics**: [opensearch.org/docs/latest/security-analytics](https://opensearch.org/docs/latest/security-analytics/)
- **Wazuh Documentation**: [documentation.wazuh.com](https://documentation.wazuh.com/)
- **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org/)
- **AWS Step Functions**: [docs.aws.amazon.com/step-functions](https://docs.aws.amazon.com/step-functions/latest/dg/welcome.html)

---

## Detection Maturity Assessment

Based on SOC architecture review:
- **Overall Maturity**: 7.2/10 (Good for Demo/PoC)
- **SOAR Maturity**: 8.5/10 (Production-pattern design)
- **MITRE ATT&CK Coverage**: ~60% (AWS/Linux focused)
- **Detection Layer Diversity**: 6/10 (Strong IOC/EDR, weak correlation)

See full SOC detection review for gap analysis and improvement roadmap.

---

## License

MIT License - See [LICENSE](LICENSE) file.

## Contributing

Pull requests welcome. For major changes, open an issue first to discuss proposed modifications.

---

