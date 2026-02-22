"""
Model Training Script for Hybrid Detection System
=================================================

This script trains ML models (Isolation Forest, Autoencoder, LSTM)
on normal/baseline security logs collected from the system.

Usage:
    1. Collect normal traffic logs into training_data.json
    2. Run: python train_models.py
    3. Models will be saved to ./models/ directory
    4. Restart ai_orchestrator.py to use trained models

Training Data Format:
    JSON file with array of log entries (normal behavior only)
"""

import json
import logging
import numpy as np
from datetime import datetime

from feature_extractor import FeatureExtractor
from ml_models import MLAnomalyDetector, LSTMSequenceDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ModelTraining")


def load_training_data(file_path="training_data.json"):
    """Load training data from JSON file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        logger.info(f"Loaded {len(data)} training samples from {file_path}")
        return data
    except FileNotFoundError:
        logger.error(f"Training data file not found: {file_path}")
        logger.info("Please create training_data.json with normal log samples.")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in training data: {e}")
        return None


def extract_features_from_logs(logs):
    """Extract feature vectors from log entries"""
    feature_extractor = FeatureExtractor(window_size_minutes=60)
    
    feature_vectors = []
    
    for i, log in enumerate(logs):
        try:
            # Extract feature vector
            feature_vector = feature_extractor.get_feature_vector(log)
            feature_vectors.append(feature_vector)
            
            if (i + 1) % 100 == 0:
                logger.info(f"Processed {i + 1}/{len(logs)} logs...")
        except Exception as e:
            logger.warning(f"Failed to extract features from log {i}: {e}")
            continue
    
    return np.array(feature_vectors)


def extract_sequences_from_logs(logs, sequence_length=10):
    """Extract sequences for LSTM training"""
    feature_extractor = FeatureExtractor(window_size_minutes=60)
    
    all_features = []
    for log in logs:
        try:
            feature_vector = feature_extractor.get_feature_vector(log)
            all_features.append(feature_vector)
        except Exception as e:
            logger.warning(f"Failed to extract features: {e}")
            continue
    
    # Create sequences
    sequences = []
    for i in range(len(all_features) - sequence_length):
        sequences.append(all_features[i:i+sequence_length])
    
    return np.array(sequences)


def train_models(training_data, model_dir="models"):
    """Train all ML models"""
    
    if not training_data or len(training_data) < 50:
        logger.error("Insufficient training data. Need at least 50 normal log samples.")
        return False
    
    logger.info(f"\n{'='*60}")
    logger.info("Starting Model Training Pipeline")
    logger.info(f"{'='*60}\n")
    
    # Step 1: Extract features
    logger.info("Step 1: Extracting features from logs...")
    X_train = extract_features_from_logs(training_data)
    
    if len(X_train) == 0:
        logger.error("No features extracted. Check training data format.")
        return False
    
    logger.info(f"Extracted {len(X_train)} feature vectors with {X_train.shape[1]} features each")
    
    # Step 2: Train Isolation Forest & Autoencoder
    logger.info("\nStep 2: Training Isolation Forest and Autoencoder...")
    ml_detector = MLAnomalyDetector(model_dir=model_dir, contamination=0.05)
    
    success = ml_detector.train(X_train, epochs_ae=50, verbose=1)
    
    if not success:
        logger.error("Model training failed!")
        return False
    
    # Step 3: Train LSTM Sequence Detector (optional)
    if len(training_data) >= 100:
        logger.info("\nStep 3: Training LSTM Sequence Detector...")
        try:
            sequences = extract_sequences_from_logs(training_data, sequence_length=10)
            
            if len(sequences) >= 10:
                lstm_detector = LSTMSequenceDetector(model_dir=model_dir)
                lstm_detector.train(sequences, epochs=30, verbose=1)
                logger.info("✓ LSTM Sequence Detector trained successfully")
            else:
                logger.warning("Not enough sequences for LSTM training (need 10+)")
        except Exception as e:
            logger.warning(f"LSTM training skipped: {e}")
    else:
        logger.info("\nStep 3: Skipping LSTM training (need 100+ samples)")
    
    logger.info(f"\n{'='*60}")
    logger.info("Model Training Complete!")
    logger.info(f"Models saved to: {model_dir}/")
    logger.info(f"{'='*60}\n")
    
    return True


def generate_sample_training_data(output_file="training_data.json", n_samples=200):
    """Generate sample training data for testing"""
    logger.info(f"Generating {n_samples} sample training logs...")
    
    import random
    from datetime import timedelta
    
    base_time = datetime.now()
    users = ['alice', 'bob', 'charlie', 'dave']
    ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
    event_types = ['Login', 'Logout', 'File_Access', 'Network_Connection']
    
    logs = []
    for i in range(n_samples):
        log = {
            "timestamp": (base_time + timedelta(seconds=i*30)).isoformat(),
            "user": random.choice(users),
            "ip": random.choice(ips),
            "event_type": random.choice(event_types),
            "status": "SUCCESS" if random.random() > 0.1 else "FAILURE",
            "event_id": f"evt_{i}"
        }
        logs.append(log)
    
    with open(output_file, 'w') as f:
        json.dump(logs, f, indent=2)
    
    logger.info(f"Sample data saved to {output_file}")
    return logs


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train ML models for anomaly detection")
    parser.add_argument('--data', type=str, default='training_data.json',
                        help='Path to training data JSON file')
    parser.add_argument('--generate-sample', action='store_true',
                        help='Generate sample training data')
    parser.add_argument('--samples', type=int, default=200,
                        help='Number of sample logs to generate')
    parser.add_argument('--model-dir', type=str, default='models',
                        help='Directory to save trained models')
    
    args = parser.parse_args()
    
    # Generate sample data if requested
    if args.generate_sample:
        training_data = generate_sample_training_data(args.data, args.samples)
    else:
        # Load training data
        training_data = load_training_data(args.data)
        
        if training_data is None:
            logger.error("Failed to load training data. Use --generate-sample to create sample data.")
            exit(1)
    
    # Train models
    success = train_models(training_data, model_dir=args.model_dir)
    
    if success:
        logger.info("\n✓ Training complete! Restart ai_orchestrator.py to use trained models.")
    else:
        logger.error("\n✗ Training failed. Check logs for details.")
        exit(1)
