import streamlit as st
import pandas as pd
import re
from urllib.parse import urlparse
import pickle

# Load the best model (Extra Trees Classifier in this case) using pickle
with open('Malicious_url_classifier.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Feature extraction functions
def extract_features(url):
    features = {}
    features['url_len'] = len(url)
    features['@'] = url.count('@')
    features['?'] = url.count('?')
    features['-'] = url.count('-')
    features['='] = url.count('=')
    features['.'] = url.count('.')
    features['#'] = url.count('#')
    features['%'] = url.count('%')
    features['+'] = url.count('+')
    features['$'] = url.count('$') 
    features['!'] = url.count('!')
    features['*'] = url.count('*')
    features[','] = url.count(',')
    features['//'] = url.count('//')

    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    features['abnormal_url'] = 0 if match else 1

    htp = urlparse(url).scheme
    features['https'] = 1 if htp == 'https' else 0

    digits = sum(c.isdigit() for c in url)
    features['digits'] = digits

    letters = sum(c.isalpha() for c in url)
    features['letters'] = letters

    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|',
                      url)
    features['Shortining_Service'] = 1 if match else 0

    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    features['having_ip_address'] = 1 if match else 0

    return features

# Streamlit app
st.title("Malicious URL Classifier")

url_input = st.text_input("Enter a URL to classify:")

if url_input:
    features = extract_features(url_input)
    feature_df = pd.DataFrame([features])
    prediction = model.predict(feature_df)[0]

    labels = {0: "Benign", 1: "Defacement", 2: "Phishing", 3: "Malware"}
    result = labels[prediction]

    st.write(f"The URL is classified as: **{result}**")

# Display model accuracy
st.subheader("Model Accuracy")

# Accuracy of the best-performing model (Extra Trees Classifier)
model_accuracy = 0.98

st.write(f"Model Accuracy: **{model_accuracy * 100}%**")
