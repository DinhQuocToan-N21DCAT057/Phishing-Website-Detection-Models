import argparse
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import joblib
import os

from feature_extractor import process_urls

def albumentations(X, corpus_t):
    for i in range(len(X)):
        print(i, "/", len(X))
        review = re.sub("[^a-zA-Z]", " ", X[i])
        review = review.lower()
        review = review.split()
        review = [ps.stem(word) for word in review if
                  word not in set(stopwords.words("english"))]  # TO REMOVE STOP WORDS LIKE THE, A ETC
        review = " ".join(review)
        corpus_t.append(review)

# Function to predict using a model
def predict_url(model, X1_data, X2_data, url_index, model_name, use_numerical=True):
    try:
        # Select input based on model type
        if use_numerical:
            pred = model.predict(X1_data[url_index:url_index + 1], verbose=0)
        else:
            pred = model.predict(X2_data[url_index:url_index + 1], verbose=0)
        label = 1 if pred >= 0.5 else 0
        return label, pred[0][0]
    except Exception as e:
        print(f"Error predicting with {model_name} for index {url_index}: {e}")
        return None, None

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='URL Phishing Detection')
    parser.add_argument('--urls', nargs='+', help='One or more URLs to check')

    args = parser.parse_args()

    #args.urls = ["https://docs.microsoft.com/en-us/sql/ssms/sql-server-management-studio-ssms"]

    # Verify TensorFlow versionpyh
    print(f"TensorFlow Version: {tf.__version__}")

    # Download NLTK stopwords if not already downloaded
    try:
        stopwords.words("english")
    except LookupError:
        print("Downloading NLTK stopwords...")
        nltk.download('stopwords')

    # Define paths
    BASE_DIR = r"D:\Hoc Tap\Giao Trinh va Bai Tap\2024-2025\HKII\ATMangNangCao\CuoiKy\LSTM-CNN-Phishing-Website"
    DATASET_PATH = r"D:\Hoc Tap\Giao Trinh va Bai Tap\2024-2025\HKII\ATMangNangCao\CuoiKy\LSTM-CNN-Phishing-Website\script\website_extracted_features.csv"  # Update if needed
    VECTORIZER_PATH = os.path.join(BASE_DIR, "tfidf_vectorizer.pkl")  # Update if saved elsewhere

    # Load the trained models
    try:
        cnn_model1 = load_model(os.path.join(BASE_DIR, "CNN_MODEL_ON_FEATURE_EXTRACTED.h5"))
        cnn_model2 = load_model(os.path.join(BASE_DIR, "CNN_MODEL_ON_NON_FEATURE_EXTRACTED.h5"))
        cnn_lstm_model1 = load_model(os.path.join(BASE_DIR, "CNN_LSTM_MODEL_ON_FEATURE_EXTRACTED.h5"))
        cnn_lstm_model2 = load_model(os.path.join(BASE_DIR, "CNN_LSTM_MODEL_ON_NON_FEATURE_EXTRACTED.h5"))
        print("Models loaded successfully")
    except Exception as e:
        print(f"Error loading models: {e}")
        print("Current directory contents:", os.listdir(BASE_DIR))
        exit()

    # Load the dataset
    try:
        if os.path.exists(DATASET_PATH):
            df = pd.read_csv(DATASET_PATH)
        elif args.urls:
            df = process_urls(args.urls, None)
    except Exception as e:
        print(f"Error extracting urls's features: {e}")
        print("If you use .csv file ensure dataset is at:", DATASET_PATH)
        exit()
    finally:
        print(f"Dataset columns: {df.columns}")

    # Preprocess numerical features (X1)
    try:
        X1 = df.drop(columns=['url', 'status'])  # Drop 'url' and 'status'
        if 'labels' in X1.columns:
            X1 = X1.drop(columns=['labels'])
        X1 = np.expand_dims(X1, axis=-1)  # Add dimension for CNN input (shape: samples, features, 1)
        print(f"Numerical features shape: {X1.shape}")
    except Exception as e:
        print(f"Error preprocessing numerical features: {e}")
        exit()

    # Preprocess URL text features (X2)
    ps = PorterStemmer()
    corpus = []

    # Extract URLs and preprocess
    try:
        X2 = df['url']
        albumentations(X2, corpus)
    except Exception as e:
        print(f"Error preprocessing URLs: {e}")
        exit()

    # Load or fit TF-IDF vectorizer
    try:
        if os.path.exists(VECTORIZER_PATH):
            cv = joblib.load(VECTORIZER_PATH)
            print("Loaded saved TF-IDF vectorizer")
        else:
            cv = TfidfVectorizer(max_features=1000)
            X2 = cv.fit_transform(corpus).toarray()
            joblib.dump(cv, VECTORIZER_PATH)
            print("Fitted and saved TF-IDF vectorizer at:", VECTORIZER_PATH)
        X2 = cv.transform(corpus).toarray()
        X2 = np.expand_dims(X2, axis=-1)  # Add dimension for CNN input (shape: samples, 1000, 1)
        print(f"Text features shape: {X2.shape}")
    except Exception as e:
        print(f"Error with TF-IDF vectorization: {e}")
        exit()

    # Example: Predict for a single URL (index 0)
    url_index = 0
    url = df['url'].iloc[url_index]
    print(f"\nPredicting for URL: {url}")

    # Predict with models
    # Numerical feature models
    label, prob = predict_url(cnn_model1, X1, X2, url_index, "CNN Model (Numerical)", use_numerical=True)
    if label is not None:
        print(f"CNN Model (Numerical) Prediction: {'Phishing' if label == 1 else 'Legitimate'} (Probability: {prob:.4f})")

    label, prob = predict_url(cnn_lstm_model1, X1, X2, url_index, "CNN-LSTM Model (Numerical)", use_numerical=True)
    if label is not None:
        print(f"CNN-LSTM Model (Numerical) Prediction: {'Phishing' if label == 1 else 'Legitimate'} (Probability: {prob:.4f})")

    # Text feature models
    label, prob = predict_url(cnn_model2, X1, X2, url_index, "CNN Model (Text)", use_numerical=False)
    if label is not None:
        print(f"CNN Model (Text) Prediction: {'Phishing' if label == 1 else 'Legitimate'} (Probability: {prob:.4f})")

    label, prob = predict_url(cnn_lstm_model2, X1, X2, url_index, "CNN-LSTM Model (Text)", use_numerical=False)
    if label is not None:
        print(f"CNN-LSTM Model (Text) Prediction: {'Phishing' if label == 1 else 'Legitimate'} (Probability: {prob:.4f})")


