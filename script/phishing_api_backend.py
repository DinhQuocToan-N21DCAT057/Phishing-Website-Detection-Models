from flask import Flask, request, jsonify
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

from feature_extractor import process_urls  # bạn cần đảm bảo file này có hàm process_urls đúng

# Download stopwords nếu chưa có
try:
    stopwords.words("english")
except LookupError:
    nltk.download("stopwords")

app = Flask(__name__)

# Đường dẫn các file cần thiết
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VECTORIZER_PATH = os.path.join(BASE_DIR, "tfidf_vectorizer.pkl")

print("BASE_DIR:", BASE_DIR)
print("Exists:", os.path.exists(os.path.join(BASE_DIR, "CNN_MODEL_ON_FEATURE_EXTRACTED.h5")))

# Load mô hình
cnn_model1 = load_model(os.path.join(BASE_DIR, "CNN_MODEL_ON_FEATURE_EXTRACTED.h5"))
cnn_model2 = load_model(os.path.join(BASE_DIR, "CNN_MODEL_ON_NON_FEATURE_EXTRACTED.h5"))
cnn_lstm_model1 = load_model(os.path.join(BASE_DIR, "CNN_LSTM_MODEL_ON_FEATURE_EXTRACTED.h5"))
cnn_lstm_model2 = load_model(os.path.join(BASE_DIR, "CNN_LSTM_MODEL_ON_NON_FEATURE_EXTRACTED.h5"))

# Load vectorizer
cv = joblib.load(VECTORIZER_PATH)

ps = PorterStemmer()

def preprocess_text_urls(X):
    corpus = []
    for url in X:
        review = re.sub("[^a-zA-Z]", " ", url)
        review = review.lower()
        review = review.split()
        review = [ps.stem(word) for word in review if word not in set(stopwords.words("english"))]
        review = " ".join(review)
        corpus.append(review)
    X2 = cv.transform(corpus).toarray()
    X2 = np.expand_dims(X2, axis=-1)
    return X2

def preprocess_numerical_features(df):
    X1 = df.drop(columns=['url'])
    if 'status' in X1.columns:
        X1 = X1.drop(columns=['status'])
    if 'labels' in X1.columns:
        X1 = X1.drop(columns=['labels'])
    X1 = np.expand_dims(X1, axis=-1)
    return X1

def predict(model, X, use_numerical=True):
    pred = model.predict(X, verbose=0)[0][0]
    label = int(pred >= 0.5)
    return label, float(pred)

@app.route("/predict", methods=["POST"])
def predict_api():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Tạo DataFrame từ URL mới
    try:
        df = process_urls([url], None)
    except Exception as e:
        return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500

    try:
        X1 = preprocess_numerical_features(df)
        X2 = preprocess_text_urls(df['url'])

        result = {
            "url": url,
            "cnn_model_numerical": dict(zip(["label", "confidence"], predict(cnn_model1, X1, True))),
            "cnn_lstm_model_numerical": dict(zip(["label", "confidence"], predict(cnn_lstm_model1, X1, True))),
            "cnn_model_text": dict(zip(["label", "confidence"], predict(cnn_model2, X2, False))),
            "cnn_lstm_model_text": dict(zip(["label", "confidence"], predict(cnn_lstm_model2, X2, False)))
        }
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
