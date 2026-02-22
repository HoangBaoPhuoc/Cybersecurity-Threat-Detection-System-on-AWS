"""
Machine Learning Models for Anomaly Detection
==============================================

This module implements multiple ML/DL models for detecting anomalies
in cybersecurity logs using features extracted from FeatureExtractor.

Models Implemented:
1. Isolation Forest - Unsupervised outlier detection
2. Autoencoder - Neural network-based reconstruction error
3. LSTM-based Sequence Detector - Time series anomaly detection

References:
- Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation forest. ICDM.
- Hawkins, S., et al. (2002). Outlier detection using replicator neural networks.
- Malhotra, P., et al. (2015). Long short term memory networks for anomaly detection in time series.
"""

import logging
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Optional: TensorFlow/Keras for Autoencoder and LSTM
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    logging.warning("TensorFlow not installed. Autoencoder and LSTM models will be disabled.")

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MLModels")


class MLAnomalyDetector:
    """
    Ensemble ML-based anomaly detector combining multiple models.
    """
    
    def __init__(self, model_dir="models", contamination=0.05):
        """
        Args:
            model_dir: Directory to save/load trained models
            contamination: Expected proportion of anomalies (for Isolation Forest)
        """
        self.model_dir = model_dir
        self.contamination = contamination
        
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize models
        self.isolation_forest = None
        self.autoencoder = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Load pre-trained models if exist
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            # Load Isolation Forest
            if_path = os.path.join(self.model_dir, "isolation_forest.pkl")
            if os.path.exists(if_path):
                with open(if_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                logger.info("Loaded Isolation Forest model")
            
            # Load Scaler
            scaler_path = os.path.join(self.model_dir, "scaler.pkl")
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Loaded feature scaler")
            
            # Load Autoencoder
            if HAS_TENSORFLOW:
                ae_path = os.path.join(self.model_dir, "autoencoder.h5")
                if os.path.exists(ae_path):
                    self.autoencoder = keras.models.load_model(ae_path)
                    logger.info("Loaded Autoencoder model")
            
            if self.isolation_forest:
                self.is_trained = True
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save Isolation Forest
            if self.isolation_forest:
                if_path = os.path.join(self.model_dir, "isolation_forest.pkl")
                with open(if_path, 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
                logger.info(f"Saved Isolation Forest to {if_path}")
            
            # Save Scaler
            scaler_path = os.path.join(self.model_dir, "scaler.pkl")
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            logger.info(f"Saved scaler to {scaler_path}")
            
            # Save Autoencoder
            if HAS_TENSORFLOW and self.autoencoder:
                ae_path = os.path.join(self.model_dir, "autoencoder.h5")
                self.autoencoder.save(ae_path)
                logger.info(f"Saved Autoencoder to {ae_path}")
                
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def train(self, X_train, epochs_ae=50, verbose=0):
        """
        Train all models on normal data.
        
        Args:
            X_train: Training data (numpy array of feature vectors from normal logs)
            epochs_ae: Number of epochs for autoencoder training
            verbose: Verbosity level
        """
        if len(X_train) < 10:
            logger.warning("Insufficient training data. Need at least 10 samples.")
            return False
        
        logger.info(f"Training models on {len(X_train)} samples...")
        
        # Fit scaler
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)
        
        # 1. Train Isolation Forest
        logger.info("Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False
        )
        self.isolation_forest.fit(X_scaled)
        logger.info("✓ Isolation Forest trained")
        
        # 2. Train Autoencoder
        if HAS_TENSORFLOW:
            logger.info("Training Autoencoder...")
            input_dim = X_scaled.shape[1]
            
            # Build autoencoder architecture
            encoder = keras.Sequential([
                layers.Dense(16, activation='relu', input_shape=(input_dim,)),
                layers.Dense(8, activation='relu'),
                layers.Dense(4, activation='relu')
            ])
            
            decoder = keras.Sequential([
                layers.Dense(8, activation='relu', input_shape=(4,)),
                layers.Dense(16, activation='relu'),
                layers.Dense(input_dim, activation='sigmoid')
            ])
            
            self.autoencoder = keras.Model(
                inputs=encoder.input,
                outputs=decoder(encoder.output)
            )
            
            self.autoencoder.compile(
                optimizer='adam',
                loss='mse'
            )
            
            # Train on normal data (learns to reconstruct normal patterns)
            self.autoencoder.fit(
                X_scaled, X_scaled,
                epochs=epochs_ae,
                batch_size=32,
                validation_split=0.1,
                verbose=verbose,
                shuffle=True
            )
            logger.info("✓ Autoencoder trained")
        
        self.is_trained = True
        self._save_models()
        
        logger.info("All models trained successfully!")
        return True
    
    def predict_isolation_forest(self, X):
        """
        Predict anomaly score using Isolation Forest.
        
        Returns:
            float: Anomaly score (0.0 to 1.0, higher = more anomalous)
        """
        if not self.isolation_forest:
            return 0.0
        
        X_scaled = self.scaler.transform([X])
        
        # Get anomaly score (negative = anomalous, positive = normal)
        score = self.isolation_forest.score_samples(X_scaled)[0]
        
        # Convert to 0-1 range (higher = more anomalous)
        # Isolation Forest scores typically range from -0.5 to 0.5
        anomaly_score = max(0.0, min(1.0, (-score + 0.5)))
        
        return anomaly_score
    
    def predict_autoencoder(self, X):
        """
        Predict anomaly score using Autoencoder reconstruction error.
        
        Returns:
            float: Anomaly score (0.0 to 1.0, higher = more anomalous)
        """
        if not HAS_TENSORFLOW or not self.autoencoder:
            return 0.0
        
        X_scaled = self.scaler.transform([X])
        
        # Get reconstruction
        reconstructed = self.autoencoder.predict(X_scaled, verbose=0)
        
        # Calculate reconstruction error (MSE)
        mse = np.mean(np.square(X_scaled - reconstructed))
        
        # Normalize to 0-1 range (using sigmoid-like function)
        # Typical MSE for normal samples: 0.01-0.1
        # Anomalies: 0.2-1.0+
        anomaly_score = 1 / (1 + np.exp(-10 * (mse - 0.15)))
        
        return float(anomaly_score)
    
    def predict(self, X, return_details=False):
        """
        Ensemble prediction combining multiple models.
        
        Args:
            X: Feature vector (numpy array)
            return_details: If True, return individual model scores
            
        Returns:
            float or dict: Combined anomaly score (0.0-1.0) or dict with details
        """
        if not self.is_trained:
            logger.warning("Models not trained. Using fallback mode.")
            return 0.0 if not return_details else {"ensemble_score": 0.0, "if_score": 0.0, "ae_score": 0.0}
        
        # Get predictions from each model
        if_score = self.predict_isolation_forest(X)
        ae_score = self.predict_autoencoder(X) if HAS_TENSORFLOW else 0.0
        
        # Ensemble: Weighted average
        weights = {
            'isolation_forest': 0.6,
            'autoencoder': 0.4 if HAS_TENSORFLOW else 0.0
        }
        
        # Normalize weights if autoencoder is not available
        if not HAS_TENSORFLOW:
            weights['isolation_forest'] = 1.0
        
        ensemble_score = (
            weights['isolation_forest'] * if_score +
            weights['autoencoder'] * ae_score
        )
        
        if return_details:
            return {
                "ensemble_score": round(ensemble_score, 3),
                "isolation_forest_score": round(if_score, 3),
                "autoencoder_score": round(ae_score, 3),
                "models_used": ["Isolation Forest"] + (["Autoencoder"] if HAS_TENSORFLOW else [])
            }
        
        return round(ensemble_score, 3)
    
    def update_online(self, X, is_anomaly=False):
        """
        Online learning: Update models with new data.
        
        Args:
            X: Feature vector
            is_anomaly: Whether this sample is labeled as anomaly
        """
        # For now, simple implementation: retrain periodically
        # In production, implement incremental learning
        pass


class LSTMSequenceDetector:
    """
    LSTM-based sequence anomaly detector for time-series patterns.
    
    This model learns normal sequences of events and detects deviations.
    Useful for detecting attack chains or unusual activity patterns.
    """
    
    def __init__(self, sequence_length=10, model_dir="models"):
        self.sequence_length = sequence_length
        self.model_dir = model_dir
        self.model = None
        self.scaler = StandardScaler()
        self.sequence_buffer = []
        
        if not HAS_TENSORFLOW:
            logger.warning("TensorFlow not available. LSTM detector disabled.")
            return
        
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained LSTM model"""
        model_path = os.path.join(self.model_dir, "lstm_detector.h5")
        if os.path.exists(model_path):
            try:
                self.model = keras.models.load_model(model_path)
                logger.info("Loaded LSTM Sequence Detector")
            except Exception as e:
                logger.error(f"Error loading LSTM model: {e}")
    
    def train(self, X_sequences, epochs=30, verbose=0):
        """
        Train LSTM on normal sequences.
        
        Args:
            X_sequences: List of sequences (each sequence is a list of feature vectors)
        """
        if not HAS_TENSORFLOW:
            return False
        
        if len(X_sequences) < 10:
            logger.warning("Insufficient sequence data for training")
            return False
        
        # Prepare data
        X_sequences = np.array(X_sequences)
        
        # Build LSTM model
        input_shape = (X_sequences.shape[1], X_sequences.shape[2])
        
        self.model = keras.Sequential([
            layers.LSTM(32, activation='relu', input_shape=input_shape, return_sequences=True),
            layers.Dropout(0.2),
            layers.LSTM(16, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(8, activation='relu'),
            layers.Dense(X_sequences.shape[2])  # Predict next feature vector
        ])
        
        self.model.compile(optimizer='adam', loss='mse')
        
        # Train (predict next in sequence)
        X_train = X_sequences[:, :-1, :]
        y_train = X_sequences[:, -1, :]
        
        self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=16,
            validation_split=0.1,
            verbose=verbose
        )
        
        # Save model
        model_path = os.path.join(self.model_dir, "lstm_detector.h5")
        self.model.save(model_path)
        logger.info(f"LSTM model saved to {model_path}")
        
        return True
    
    def predict(self, feature_vector):
        """
        Add new feature vector to sequence buffer and predict anomaly.
        
        Returns:
            float: Anomaly score based on sequence deviation
        """
        if not HAS_TENSORFLOW or not self.model:
            return 0.0
        
        # Add to buffer
        self.sequence_buffer.append(feature_vector)
        
        # Keep only recent sequence
        if len(self.sequence_buffer) > self.sequence_length:
            self.sequence_buffer.pop(0)
        
        # Need full sequence to predict
        if len(self.sequence_buffer) < self.sequence_length:
            return 0.0
        
        # Predict next vector
        sequence = np.array(self.sequence_buffer[:-1]).reshape(1, -1, len(feature_vector))
        predicted = self.model.predict(sequence, verbose=0)[0]
        
        # Calculate prediction error
        actual = self.sequence_buffer[-1]
        mse = np.mean(np.square(predicted - actual))
        
        # Convert to anomaly score
        anomaly_score = 1 / (1 + np.exp(-5 * (mse - 0.2)))
        
        return float(anomaly_score)


if __name__ == "__main__":
    # Test ML Models
    logger.info("Testing ML Anomaly Detector...")
    
    # Generate synthetic training data (normal behavior)
    np.random.seed(42)
    n_samples = 500
    n_features = 25
    
    # Normal data: centered around 0.5 with small variance
    X_train = np.random.normal(loc=0.5, scale=0.1, size=(n_samples, n_features))
    X_train = np.clip(X_train, 0, 1)  # Clip to valid range
    
    # Test data: mix of normal and anomalous
    X_test_normal = np.random.normal(loc=0.5, scale=0.1, size=(10, n_features))
    X_test_anomaly = np.random.normal(loc=0.8, scale=0.3, size=(10, n_features))
    X_test_anomaly = np.clip(X_test_anomaly, 0, 1)
    
    # Train detector
    detector = MLAnomalyDetector()
    detector.train(X_train, epochs_ae=10, verbose=0)
    
    # Test predictions
    print("\n=== Testing Normal Samples ===")
    for i, x in enumerate(X_test_normal[:3]):
        result = detector.predict(x, return_details=True)
        print(f"Sample {i+1}: {result}")
    
    print("\n=== Testing Anomalous Samples ===")
    for i, x in enumerate(X_test_anomaly[:3]):
        result = detector.predict(x, return_details=True)
        print(f"Sample {i+1}: {result}")
    
    logger.info("✓ ML Models test completed")
