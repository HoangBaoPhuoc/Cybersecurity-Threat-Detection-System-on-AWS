import json
import time
import random
import datetime
from kafka import KafkaProducer

# Configuration
KAFKA_BROKERS = ['localhost:9092'] # Replace with AWS MSK Brokers
TOPIC_NAME = 'system-logs'

def create_producer():
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        return producer
    except Exception as e:
        print(f"Failed to connect to Kafka: {e}")
        return None

def generate_log():
    event_types = ['LOGIN', 'FILE_ACCESS', 'NETWORK_CONNECTION', 'PROCESS_START']
    statuses = ['SUCCESS', 'FAILURE']
    users = ['admin', 'jdoe', 'service_account', 'unknown_user']
    
    log = {
        'timestamp': datetime.datetime.now().isoformat(),
        'event_id': str(random.randint(1000, 9999)),
        'event_type': random.choice(event_types),
        'user': random.choice(users),
        'src_ip': f"192.168.1.{random.randint(1, 255)}",
        'status': random.choice(statuses),
        'message': "Action performed on system."
    }
    
    # Simulate an anomaly
    if random.random() < 0.05:
        log['status'] = 'FAILURE'
        log['user'] = 'root'
        log['message'] = "Multiple failed authentication attempts detected."
        log['is_anomaly'] = True
        
    return log

def main():
    producer = create_producer()
    if not producer:
        print("Producer creation failed. Exiting.")
        return

    print(f"Starting log stream to topic: {TOPIC_NAME}...")
    try:
        while True:
            log_data = generate_log()
            producer.send(TOPIC_NAME, log_data)
            print(f"Sent: {log_data}")
            time.sleep(1) # Send 1 log per second
    except KeyboardInterrupt:
        print("Stopping producer...")
    finally:
        producer.close()

if __name__ == "__main__":
    main()
