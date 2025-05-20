# Base image
FROM python:3.10-slim

# Cài các gói hệ thống cần thiết
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Tạo thư mục làm việc trong container
WORKDIR /app

# Clone project từ Git (thay LINK_GIT = repo của bạn)
RUN git clone https://github.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models /app

# Cài thư viện Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Tải stopwords cho nltk
RUN python -m nltk.downloader stopwords

# Chạy ứng dụng Flask
CMD ["python", "script/phishing_api_backend.py"]
