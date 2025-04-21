#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multioutput import MultiOutputClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import re
import os
import sys
import argparse
import logging
import time
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"train_model_{datetime.now().strftime('%Y%m%d')}.log")
    ]
)
logger = logging.getLogger("train-model")

# Import helper functions
from utils.data_utils import preprocess_data

def train_security_model(df, output_dir="models", n_estimators=100, max_features=5000):
    """
    Train a security analysis model and save it.

    Parameters:
        df (DataFrame): Preprocessed data
        output_dir (str): Directory to save the trained model
        n_estimators (int): Number of trees in the random forest
        max_features (int): Maximum number of features in TF-IDF

    Returns:
        tuple: (model, vectorizer, score)
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created directory {output_dir}")

    # Define target variables
    targets = [
        'Vulnerability_Types',
        'Mitigation_Strategies',
        'Improvement_Suggestions',
        'Assessment_Tools_Used'
    ]

    # Check for target columns
    for col in targets:
        if col not in df.columns:
            raise ValueError(f"Column {col} not found in dataset")

    # Create TF-IDF features
    logger.info(f"Creating TF-IDF features (max_features={max_features})...")
    vectorizer = TfidfVectorizer(max_features=max_features, ngram_range=(1, 2))
    X = vectorizer.fit_transform(df['combined_features'])

    # Prepare target variables
    logger.info("Preparing target variables...")
    y = df[targets]

    # Split data into training and test sets
    logger.info("Splitting data into training and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train a multi-output classifier with RandomForest
    logger.info(f"Training model (n_estimators={n_estimators})...")
    start_time = time.time()
    base_classifier = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
    model = MultiOutputClassifier(base_classifier)
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    # Evaluate the model
    logger.info(f"Evaluating model...")
    score = model.score(X_test, y_test)
    logger.info(f"Model accuracy: {score:.4f}")
    logger.info(f"Training time: {training_time:.2f} seconds ({training_time/60:.2f} minutes)")

    # Save the model and vectorizer
    logger.info(f"Saving model and vectorizer to {output_dir}...")
    joblib.dump(model, os.path.join(output_dir, "security_model.joblib"))
    joblib.dump(vectorizer, os.path.join(output_dir, "vectorizer.joblib"))

    # Save category mapping
    with open(os.path.join(output_dir, "category_map.txt"), 'w') as f:
        for category, cat_id in df['category_id'].items():
            f.write(f"{category},{cat_id}\n")

    # Save training info
    with open(os.path.join(output_dir, "training_info.txt"), 'w') as f:
        f.write(f"Training date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Number of records: {len(df)}\n")
        f.write(f"Training set size: {len(X_train)}\n")
        f.write(f"Test set size: {len(X_test)}\n")
        f.write(f"Number of features: {X.shape[1]}\n")
        f.write(f"Model accuracy: {score:.4f}\n")
        f.write(f"Number of trees: {n_estimators}\n")
        f.write(f"Number of categories: {len(df['Category'].unique())}\n")
        f.write(f"Training time: {training_time:.2f} seconds ({training_time/60:.2f} minutes)\n")

    return model, vectorizer, score, training_time

def test_model_with_examples(model, vectorizer, examples):
    """
    Test the trained model with code examples.

    Parameters:
        model: The trained model
        vectorizer: TF-IDF vectorizer
        examples: Dictionary of code examples: { example_name: (code, category) }
    """
    logger.info("Testing model with examples...")

    for name, (code, category) in examples.items():
        logger.info(f"Testing example: {name} (Category: {category})")

        # Extract security patterns from code
        from utils.code_analyzer import extract_security_patterns

        patterns = extract_security_patterns(code)
        feature_text = f"Category: {category} "
        for key, value in patterns.items():
            if value:
                feature_text += f"{key} "

        # Transform features using the trained vectorizer
        X = vectorizer.transform([feature_text])

        # Predict using the trained model
        predictions = model.predict(X)

        # Print results
        logger.info(f"Analysis results for example: {name}")
        logger.info(f"Vulnerabilities: {predictions[0][0]}")
        logger.info(f"Mitigation Strategies: {predictions[0][1]}")
        logger.info(f"Improvement Suggestions: {predictions[0][2]}")
        logger.info(f"Assessment Tools: {predictions[0][3]}")
        logger.info("-" * 50)

def main():
    """Main execution point."""

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Train a mobile application security analysis model")
    parser.add_argument("--data", type=str, default="data/Mobile_Security_Dataset.csv", help="Path to the data file")
    parser.add_argument("--output", type=str, default="models", help="Directory to save the trained model")
    parser.add_argument("--trees", type=int, default=100, help="Number of trees in the random forest")
    parser.add_argument("--features", type=int, default=5000, help="Maximum number of features in TF-IDF")
    parser.add_argument("--test", action="store_true", help="Test the model after training")

    args = parser.parse_args()

    # Check for data file
    if not os.path.exists(args.data):
        logger.error(f"Error: Data file '{args.data}' not found.")
        sys.exit(1)

    # Process data
    logger.info(f"Loading data from {args.data}...")
    df, category_map = preprocess_data(args.data)

    # Display basic info about the data
    logger.info(f"Dataset shape: {df.shape}")
    logger.info(f"Available columns: {df.columns.tolist()}")
    logger.info(f"Number of unique categories: {len(df['Category'].unique())}")

    # Train the model
    logger.info("Starting model training...")
    model, vectorizer, score, training_time = train_security_model(
        df,
        output_dir=args.output,
        n_estimators=args.trees,
        max_features=args.features
    )

    logger.info(f"Model training completed! Accuracy: {score:.4f}")
    logger.info(f"Training took {training_time:.2f} seconds ({training_time/60:.2f} minutes)")

    # Test the model with examples if requested
    if args.test:
        # Test examples
        examples = {
            "sql_injection": (
                """
                function authenticateUser(username, password) {
                  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
                  connection.query(query, (err, results) => {
                    if (results.length > 0) {
                      req.session.user = results[0];
                      return true;
                    }
                    return false;
                  });
                }
                """,
                "Finance"
            ),
            "encryption_missing": (
                """
                function storeUserData(userData) {
                  const user = {
                    name: userData.name,
                    creditCard: userData.creditCardNumber,
                    ssn: userData.socialSecurityNumber
                  };
                  localStorage.setItem('userData', JSON.stringify(user));
                }
                """,
                "Finance"
            ),
            "secure_communication": (
                """
                function sendHealthData(patientData) {
                  const data = new FormData();
                  data.append('patientId', patientData.id);
                  data.append('diagnosis', patientData.diagnosis);
                  data.append('treatment', patientData.treatment);
                  
                  fetch('https://health-api.example.com/patients', {
                    method: 'POST',
                    body: data,
                    headers: {
                      'Authorization': `Bearer ${getToken()}`,
                      'Content-Type': 'application/json'
                    }
                  });
                }
                """,
                "Health"
            )
        }

        test_model_with_examples(model, vectorizer, examples)

if __name__ == "__main__":
    main()