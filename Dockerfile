# Base image
FROM python:3.10-slim

# Cài gói hệ thống để hỗ trợ biên dịch và xử lý
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    git \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Tạo thư mục làm việc
WORKDIR /app

# Copy toàn bộ project vào container
COPY . .

# Cài đặt thư viện Python
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Tải stopwords cho nltk
RUN python -m nltk.downloader stopwords

EXPOSE 5000

# Mặc định chạy app bằng Python
CMD ["python", "script/phishing_api_backend.py"]
