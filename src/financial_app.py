import time
import random
import logging
import json
import threading
from datetime import datetime
from flask import Flask, jsonify, request

# Configure logging
LOG_FILE = "/var/log/financial_app.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Flask App for Real Network Activity
app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"status": "running", "service": "financial-app"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/transaction', methods=['POST'])
def create_transaction():
    # Endpoint to simulate receiving external transaction requests
    # This creates real incoming network traffic for Metricbeat to see
    data = request.json
    return jsonify({"status": "processed", "transaction_id": f"txn-{random.randint(10000, 99999)}"}), 201

def run_flask():
    print("Starting Flask API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

users = ["admin", "alice", "bob", "charlie", "dave"]
actions = ["LOGIN", "TRANSFER", "WITHDRAW", "DEPOSIT", "VIEW_BALANCE"]
status = ["SUCCESS", "FAILED"]

def generate_log():
    user = random.choice(users)
    action = random.choice(actions)
    
    # Simulate Account Takeover (Brute Force)
    if random.random() < 0.1:
        action = "LOGIN"
        result = "FAILED"
        for _ in range(5):
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "user": user,
                "action": action,
                "status": result,
                "ip": f"192.168.1.{random.randint(100, 200)}",
                "device_id": f"dev-{random.randint(1000, 9999)}"
            }
            logging.info(json.dumps(log_entry))
            time.sleep(0.5)
        return

    # Simulate Data Leak (Insider Threat)
    # Scenario: Insider exporting sensitive customer data
    if random.random() < 0.03: 
        action = "EXPORT_DATA"
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": "admin", # Privileged user
            "action": action,
            "status": "SUCCESS",
            "ip": "10.0.0.50", # Internal IP
            "details": "Exported 50,000 customer records"
        }
        logging.info(json.dumps(log_entry))
        return

    # Simulate Malware / Botnet Access (External Threat)
    # Scenario: Access from a known C2 IP (Simulated)
    if random.random() < 0.02:
        action = "API_CALL"
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": "unknown",
            "action": action,
            "status": "SUCCESS", 
            "ip": "185.159.83.24", # Example malicious IP (Cobalt Strike C2)
            "details": "Executed remote command"
        }
        logging.info(json.dumps(log_entry))
        return

    # Standard / Fraud Simulation (Existing)
    # Simulate High Value Transfer (Potential Fraud)
    amount = 0
    if action in ["TRANSFER", "WITHDRAW"]:
        if random.random() < 0.05:
            amount = random.randint(100000, 1000000) # High amount
        else:
            amount = random.randint(10, 5000)
    
    result = "SUCCESS"
    if random.random() < 0.05:
        result = "FAILED"

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action": action,
        "amount": amount,
        "status": result,
        "ip": f"10.0.0.{random.randint(2, 254)}"
    }
    
    logging.info(json.dumps(log_entry))

if __name__ == "__main__":
    print(f"Starting Financial App Simulator. Logging to {LOG_FILE}...")
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Run log generation loop
    while True:
        generate_log()
        time.sleep(random.randint(1, 5))
