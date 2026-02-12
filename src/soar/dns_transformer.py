import os
import json
import gzip
import base64
import urllib.request
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
OPENSEARCH_HOST = os.environ['OPENSEARCH_HOST']
OPENSEARCH_INDEX = "dns-logs"
OPENSEARCH_USER = "admin" 
OPENSEARCH_PASS = "Admin123!" 

def lambda_handler(event, context):
    """
    Transforms Route53 Resolver Query Logs (from CloudWatch) and sends to OpenSearch.
    Uses standard library urllib to avoid 'No module named requests' error in Lambda.
    """
    try:
        # CloudWatch Logs data is base64 encoded and gzipped
        cw_data = event['awslogs']['data']
        compressed_payload = base64.b64decode(cw_data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        payload = json.loads(uncompressed_payload)
        
        log_events = payload.get('logEvents', [])
        
        for log_event in log_events:
            try:
                message = log_event['message']
                
                # Try to parse properties from the space-delimited string common in Route53 Logs
                # Format: version account_id interface_id srcaddr srcport query_timestamp query_name query_type query_class rcode transport protocol
                # Example: 1.0 123456789012 eni-123 10.0.1.5 12345 2023-10-01T... example.com A IN NOERROR UDP UDP
                
                dns_data = {}
                parts = message.split(' ')
                
                if len(parts) >= 10:
                    dns_data = {
                        "version": parts[0],
                        "account_id": parts[1],
                        "interface_id": parts[2],
                        "src_ip": parts[3],
                        "src_port": parts[4],
                        "timestamp": parts[5],
                        "query_name": parts[6],
                        "query_type": parts[7],
                        "query_class": parts[8],
                        "rcode": parts[9],
                        "transport": parts[10] if len(parts) > 10 else "UNKNOWN"
                    }
                else:
                    # Fallback if not matching expected format
                    dns_data = {"raw_message": message}

                # Construct Document
                document = {
                    "timestamp": datetime.utcfromtimestamp(log_event['timestamp'] / 1000.0).isoformat(),
                    "type": "DNSQuery",
                    "src_ip": dns_data.get('src_ip'),
                    "query_name": dns_data.get('query_name'),
                    "query_type": dns_data.get('query_type'),
                    "rcode": dns_data.get('rcode'),
                    "service": "route53-resolver",
                    "raw_data": dns_data
                }
                
                # Send to OpenSearch
                url = f"https://{OPENSEARCH_HOST}/{OPENSEARCH_INDEX}/_doc"
                
                # Basic Auth Header
                auth_str = f"{OPENSEARCH_USER}:{OPENSEARCH_PASS}"
                b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {b64_auth}"
                }
                
                req = urllib.request.Request(
                    url, 
                    data=json.dumps(document).encode('utf-8'), 
                    headers=headers, 
                    method='POST'
                )
                
                # Send Request (Ignore certificate errors for demo self-signed certs if needed, 
                # but urllib validates by default. Context can be added to skip verification)
                import ssl
                context_ssl = ssl.create_default_context()
                context_ssl.check_hostname = False
                context_ssl.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(req, context=context_ssl) as res:
                    response_body = res.read()
                    # logger.info(f"Indexed: {response_body}")

            except Exception as e:
                logger.error(f"Error parse/send log event: {str(e)}")
                continue

        return {"statusCode": 200, "body": "Processed"}

    except Exception as e:
        logger.error(f"Error processing CW Event: {str(e)}")
        raise e
