import requests
import threading
import time
import logging
from flask import Flask, jsonify

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MCPServer")

app = Flask(__name__)

# Constants
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
UPDATE_INTERVAL = 3600  # 1 Hour

class ThreatFeedManager:
    def __init__(self):
        self.threat_ips = set()
        self.lock = threading.Lock()
        self.last_update = 0

    def update_feeds(self):
        """
        Downloads the latest C2 IP Blocklist from Abuse.ch
        """
        logger.info("Updating Threat Intelligence Feeds...")
        try:
            response = requests.get(FEODO_TRACKER_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # Extract IPs from the list of dicts
                new_ips = {entry['ip_address'] for entry in data}
                
                with self.lock:
                    self.threat_ips = new_ips
                    self.last_update = time.time()
                
                logger.info(f"Updated Feed. Total Malicious IPs: {len(self.threat_ips)}")
            else:
                logger.error(f"Failed to fetch feed. Status: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating feed: {e}")

    def start_background_updater(self):
        def loop():
            while True:
                self.update_feeds()
                time.sleep(UPDATE_INTERVAL)
        
        t = threading.Thread(target=loop, daemon=True)
        t.start()
    
    def is_malicious(self, ip):
        with self.lock:
            return ip in self.threat_ips

# Initialize Feed Manager
feed_manager = ThreatFeedManager()
feed_manager.start_background_updater()

# Static Mock Data (Fallback)
MOCK_CVE_DB = {
    "CVE-2023-1234": {"cvss": 9.8, "description": "Remote Code Execution in WebLogic"},
}

@app.route('/ip/<ip_address>', methods=['GET'])
def lookup_ip(ip_address):
    """
    Check IP against Real-Time Threat Feed.
    """
    is_threat = feed_manager.is_malicious(ip_address)
    
    result = {
        "ip": ip_address,
        "risk": "HIGH" if is_threat else "UNKNOWN",
        "source": "Abuse.ch Feodo Tracker" if is_threat else "Local Cache",
        "last_feed_update": time.ctime(feed_manager.last_update)
    }
    
    return jsonify(result)

@app.route('/cve/<cve_id>', methods=['GET'])
def lookup_cve(cve_id):
    """
    Look up CVE details (Mock).
    """
    data = MOCK_CVE_DB.get(cve_id, {"cvss": 0.0, "description": "CVE not found"})
    return jsonify({"cve_id": cve_id, **data})

@app.route('/update', methods=['POST'])
def force_update():
    """
    Force trigger a feed update.
    """
    threading.Thread(target=feed_manager.update_feeds).start()
    return jsonify({"status": "Update Triggered"})

if __name__ == '__main__':
    print("Starting Real-Time MCP Server on port 8000...")
    app.run(host='0.0.0.0', port=8000)
