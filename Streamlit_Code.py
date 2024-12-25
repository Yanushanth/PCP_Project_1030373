import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
from math import log2
import re
import os

# Load the trained model and feature names
model_path = "/home/jrd/Desktop/TRY/trained_model.pkl"
feature_names_path = "/home/jrd/Desktop/TRY/feature_names.pkl"

if not os.path.exists(model_path) or not os.path.exists(feature_names_path):
    st.error("Model or feature names file not found. Please check the paths.")
    st.stop()

model = joblib.load(model_path)
feature_names = joblib.load(feature_names_path)

# Feature extraction function (same as used for training)
def extract_features(url):
    if not isinstance(url, str) or pd.isna(url):
        return {
            "url_length": 0,
            "num_digits": 0,
            "num_special_chars": 0,
            "has_https": 0,
            "num_subdomains": 0,
            "has_suspicious_keywords": 0,
            "url_entropy": 0,
            "domain_length": 0,
            "path_length": 0,
            "presence_of_ip": 0,
            "tld": "",
            "num_query_params": 0,
            "has_encoded_chars": 0,
            "path_depth": 0,
            "has_suspicious_substrings": 0,
            "has_malicious_file_extension": 0
        }

    parsed_url = urlparse(url)
    path = parsed_url.path
    query = parsed_url.query

    # Calculate entropy
    try:
        probabilities = [float(url.count(c)) / len(url) for c in set(url)]
        url_entropy = -sum(p * log2(p) for p in probabilities)
    except ValueError:
        url_entropy = 0

    # Check for IP address
    def contains_ip(url):
        ip_pattern = re.compile(r"(?:\\d{1,3}\\.){3}\\d{1,3}")
        return int(bool(ip_pattern.search(url)))

    # Extract TLD
    tld = parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else ""

    # Check for encoded characters
    def has_encoded_chars(url):
        return int("%" in url)

    # Check for suspicious substrings
    def has_suspicious_substrings(url):
        suspicious_substrings = ["@", "-", "_", "~"]
        return int(any(substring in url for substring in suspicious_substrings))

    # Check for malicious file extensions
    def has_malicious_file_extension(url):
        malicious_extensions = [".exe", ".zip", ".js", ".rar", ".bat"]
        return int(any(url.lower().endswith(ext) for ext in malicious_extensions))

    return {
        "url_length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(not c.isalnum() for c in url),
        "has_https": int("https" in url.lower()),
        "num_subdomains": url.count('.'),
        "has_suspicious_keywords": int(any(keyword in url.lower() for keyword in ["login", "secure", "account", "update"])),
        "url_entropy": url_entropy,
        "domain_length": len(parsed_url.netloc),
        "path_length": len(path),
        "presence_of_ip": contains_ip(url),
        "tld": tld,
        "num_query_params": len(query.split('&')) if query else 0,
        "has_encoded_chars": has_encoded_chars(url),
        "path_depth": len(path.split('/')) - 1 if path else 0,
        "has_suspicious_substrings": has_suspicious_substrings(url),
        "has_malicious_file_extension": has_malicious_file_extension(url)
    }

# Streamlit web app
st.title("URL Classifier")
st.subheader("Enter the URL or paste the URL below")

# URL input bar
url_input = st.text_input("Enter URL:", "")

if st.button("Classify"):
    if url_input:
        # Extract features
        features = extract_features(url_input)
        features_df = pd.DataFrame([features])

        # Ensure compatibility with the model
        features_df = pd.get_dummies(features_df, columns=["tld"], drop_first=True)

        # Align with model's feature names
        for col in feature_names:
            if col not in features_df.columns:
                features_df[col] = 0  # Add missing columns with default value

        features_df = features_df[feature_names]  # Ensure column order matches

        # Predict using the loaded model
        try:
            prediction = model.predict(features_df)[0]

            # Display the result
            if prediction == "benign":
                st.success("The URL is classified as **Benign**.")
            else:
                st.error("The URL is classified as **Malicious**.")
        except Exception as e:
            st.error(f"An error occurred during prediction: {e}")
    else:
        st.warning("Please enter a URL to classify.")

