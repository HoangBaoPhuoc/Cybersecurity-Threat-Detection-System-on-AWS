import json
import logging
import os
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session

logger = logging.getLogger("BedrockAgentLambda")
logger.setLevel(logging.INFO)

BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
BEDROCK_EMBEDDING_MODEL = os.getenv("BEDROCK_EMBEDDING_MODEL", "amazon.titan-embed-text-v1")
OPENSEARCH_ENDPOINT = os.getenv("OPENSEARCH_ENDPOINT", "")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "ir-playbooks")
OPENSEARCH_TOP_K = int(os.getenv("OPENSEARCH_TOP_K", "3"))
OPENSEARCH_VECTOR_FIELD = os.getenv("OPENSEARCH_VECTOR_FIELD", "vector")
PLAYBOOK_BUCKET = os.getenv("PLAYBOOK_BUCKET", "")
DEFAULT_PLAYBOOK_KEY = os.getenv("DEFAULT_PLAYBOOK_KEY", "playbooks/default.md")
JIRA_MCP_URL = os.getenv("JIRA_MCP_URL", "")

ALLOWED_ACTIONS = set(
    action.strip()
    for action in os.getenv("ALLOWED_ACTIONS", "BLOCK_WAF,RESTRICT_IAM,RUN_SSM").split(",")
    if action.strip()
)

LAMBDA_ACTIONS = {
    "BLOCK_WAF": os.getenv("LAMBDA_BLOCK_WAF_ARN", ""),
    "RESTRICT_IAM": os.getenv("LAMBDA_RESTRICT_IAM_ARN", ""),
    "RUN_SSM": os.getenv("LAMBDA_RUN_SSM_ARN", ""),
    "QUARANTINE_SG": os.getenv("LAMBDA_QUARANTINE_SG_ARN", "")
}


def _bedrock_client():
    return boto3.client("bedrock-runtime")


def _embedding_for(text):
    client = _bedrock_client()
    payload = json.dumps({"inputText": text})
    response = client.invoke_model(modelId=BEDROCK_EMBEDDING_MODEL, body=payload)
    body = json.loads(response["body"].read())
    return body.get("embedding", [])


def _sign_request(method, url, body):
    session = Session()
    credentials = session.get_credentials()
    region = os.getenv("AWS_REGION", "us-east-1")
    request = AWSRequest(method=method, url=url, data=body, headers={"Host": OPENSEARCH_ENDPOINT})
    SigV4Auth(credentials, "es", region).add_auth(request)
    return request


def _opensearch_knn(vector):
    if not OPENSEARCH_ENDPOINT:
        return []

    query = {
        "size": OPENSEARCH_TOP_K,
        "query": {
            "knn": {
                "field": OPENSEARCH_VECTOR_FIELD,
                "query_vector": vector,
                "k": OPENSEARCH_TOP_K
            }
        }
    }

    url = f"https://{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_search"
    body = json.dumps(query).encode("utf-8")
    signed = _sign_request("POST", url, body)

    req = urllib.request.Request(url, data=body, method="POST")
    for header, value in signed.headers.items():
        req.add_header(header, value)
    req.add_header("Content-Type", "application/json")

    with urllib.request.urlopen(req, timeout=5) as response:
        payload = json.loads(response.read())
    return payload.get("hits", {}).get("hits", [])


def _fetch_playbook(s3_key):
    if not PLAYBOOK_BUCKET or not s3_key:
        return ""
    s3 = boto3.client("s3")
    response = s3.get_object(Bucket=PLAYBOOK_BUCKET, Key=s3_key)
    return response["Body"].read().decode("utf-8")


def _build_prompt(event, playbooks):
    return (
        "You are an AI incident response orchestrator. "
        "Use ONLY the provided playbooks to decide actions. "
        "Return JSON with fields: actions (list), reasoning, jira_summary, jira_description.\n\n"
        f"Event: {json.dumps(event)}\n\n"
        f"Playbooks:\n{playbooks}"
    )


def _invoke_claude(prompt):
    client = _bedrock_client()
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 800,
        "temperature": 0.2,
        "messages": [{"role": "user", "content": prompt}]
    }
    response = client.invoke_model(modelId=BEDROCK_MODEL_ID, body=json.dumps(body))
    payload = json.loads(response["body"].read())
    content = payload.get("content", [])
    if content and isinstance(content, list):
        return content[0].get("text", "")
    return payload.get("completion", "")


def _parse_agent_output(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Bedrock output not JSON. Using fallback response.")
        return {
            "actions": [],
            "reasoning": text,
            "jira_summary": "SOC Alert - Manual Review",
            "jira_description": text
        }


def _invoke_action(action, event):
    arn = LAMBDA_ACTIONS.get(action, "")
    if not arn:
        return {"action": action, "status": "SKIPPED", "reason": "Missing ARN"}

    client = boto3.client("lambda")
    response = client.invoke(
        FunctionName=arn,
        InvocationType="RequestResponse",
        Payload=json.dumps({"original_event": event}).encode("utf-8")
    )
    body = response.get("Payload").read().decode("utf-8")
    return {"action": action, "status": "INVOKED", "response": body}


def _create_jira_ticket(summary, description, priority="High"):
    if not JIRA_MCP_URL:
        return {"status": "SKIPPED", "reason": "Missing JIRA_MCP_URL"}

    payload = json.dumps({
        "summary": summary,
        "description": description,
        "priority": priority
    }).encode("utf-8")

    req = urllib.request.Request(f"{JIRA_MCP_URL}/tickets", data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read())
    except Exception as exc:
        logger.error(f"Jira MCP call failed: {exc}")
        return {"status": "ERROR", "reason": str(exc)}


def lambda_handler(event, context):
    logger.info("Agentic AI triggered")

    event_text = json.dumps(event)
    embedding = _embedding_for(event_text)
    hits = _opensearch_knn(embedding) if embedding else []

    playbook_texts = []
    for hit in hits:
        source = hit.get("_source", {})
        s3_key = source.get("s3_key")
        if s3_key:
            playbook_texts.append(_fetch_playbook(s3_key))

    if not playbook_texts:
        playbook_texts.append(_fetch_playbook(DEFAULT_PLAYBOOK_KEY))

    prompt = _build_prompt(event, "\n---\n".join(playbook_texts))
    agent_text = _invoke_claude(prompt)
    agent_output = _parse_agent_output(agent_text)

    actions = [action for action in agent_output.get("actions", []) if action in ALLOWED_ACTIONS]
    action_results = [_invoke_action(action, event) for action in actions]

    jira = _create_jira_ticket(
        agent_output.get("jira_summary", "SOC Alert"),
        agent_output.get("jira_description", agent_output.get("reasoning", ""))
    )

    return {
        "status": "SUCCESS",
        "actions": actions,
        "action_results": action_results,
        "jira": jira,
        "reasoning": agent_output.get("reasoning", "")
    }
