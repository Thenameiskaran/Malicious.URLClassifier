# Malicious URL Classifier


The Malicious URL Classifier is a tool designed to identify malicious URLs using machine learning. This project preprocesses a dataset, trains a model, and stores it as a .joblib file for efficient usage. The classifier supports real-time prediction and provides a user-friendly interface for deployment.

---

## Features

- Preprocessing: Cleans and tokenizes URL data for feature extraction.
- Feature Engineering: Extracts lexical, content-based, and host-based features.
- Machine Learning Models: Includes models like Logistic Regression, Random Forest, and Gradient Boosting.
- Joblib Serialization: Saves and loads trained models using `.joblib` for efficiency.
- Deployment Ready: Lightweight and deployable via Flask/Streamlit.

---

## Technologies Used

- Python 3.11
- Scikit-learn: For model training and evaluation.
- Pandas & NumPy: For data manipulation and preprocessing.
- NLTK: For text processing and tokenization.
- Streamlit: For creating a user-friendly interface.
- Joblib: For saving and loading models efficiently.

---

## Setup Instructions

1. Clone the Repository

git clone https://github.com/Thenameiskaran/Malicious-URL-Classifier.git

cd Malicious-URL-Classifier

2. Install Dependencies

pip install -r requirements.txt

3. Download the Dataset

Download the dataset from Kaggle Malicious URLs Dataset.

4. Run the Training Script

Preprocess the dataset, train the model, and generate the .joblib file:
python Malicius url Classifier.py

5. Run the Application

Use the generated models/malicious_url_model.joblib file to make predictions via the application:

python app.py




