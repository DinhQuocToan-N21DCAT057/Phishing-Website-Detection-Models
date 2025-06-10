import os

import torch
from transformers import BertTokenizer, BertModel

# Thiết lập device (CPU)
device = torch.device('cpu')
print(f"Using device: {device}")

# Đường dẫn tương đối
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# Định nghĩa mô hình Transformer
class Transformer(torch.nn.Module):
    def __init__(self, transformer):
        super(Transformer, self).__init__()
        self.transformer = transformer
        self.fc = torch.nn.Sequential(
            torch.nn.Linear(768, 512),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.3),
            torch.nn.Linear(512, 1),
            torch.nn.Sigmoid()
        )

    def forward(self, input_ids, attention_mask, numerical_features=None):
        transformer_output = self.transformer(input_ids=input_ids, attention_mask=attention_mask).pooler_output
        return self.fc(transformer_output)


# Hàm dự đoán URL
def transformers_predict(urls, model, tokenizer, max_length=64, threshold=0.5):
    """
    Dự đoán URL là Phishing hoặc Legitimate.

    Args:
        urls: str hoặc list of str, URL(s) cần dự đoán
        model: Transformer model đã load
        tokenizer: BertTokenizer
        max_length: Độ dài tối đa của token (default: 64)
        threshold: Ngưỡng phân loại (default: 0.5)

    Returns:
        list of dict: [{'url': str, 'prediction': str, 'probability': float}, ...]
    """
    pred, prob = "", 0
    model.eval()
    if isinstance(urls, str):
        urls = [urls]

    # Xử lý URL đầu vào
    urls = [str(url).strip() if url else 'placeholder' for url in urls]

    # Token hóa
    try:
        encoding = tokenizer(
            urls,
            max_length=max_length,
            padding=True,
            truncation=True,
            return_tensors='pt'
        )
    except Exception as e:
        return -1, 0

    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)

    # Dự đoán
    with torch.no_grad():
        outputs = model(input_ids, attention_mask).squeeze()

    # Fix: Handle both single prediction and batch predictions
    if outputs.dim() == 0:  # Single prediction (0-d tensor)
        outputs = outputs.unsqueeze(0)  # Convert to 1-d tensor

    outputs_numpy = outputs.cpu().numpy()

    # Ensure outputs_numpy is always iterable
    if outputs_numpy.ndim == 0:
        outputs_numpy = [outputs_numpy.item()]

    # Xử lý output
    predictions = []
    for url, prob in zip(urls, outputs_numpy):
        pred = 1 if prob >= threshold else 0

    return pred, float(prob)


def transformers_load_model(model_path, model_name, tokenizer_name):
    try:
        tokenizer = BertTokenizer.from_pretrained(tokenizer_name)
        transformer_model = BertModel.from_pretrained(model_name)
        model = Transformer(transformer_model)

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file {model_path} not found")

        model.load_state_dict(torch.load(model_path, map_location=device))
        model.to(device)
        print(f"Model loaded successfully from {model_path}")
    except Exception as e:
        print(f"Error loading model or tokenizer: {e}")
        exit(1)

    return model, tokenizer


if __name__ == "__main__":
    # Load tokenizer và model
    try:
        tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        transformer_model = BertModel.from_pretrained('bert-base-uncased')
        model = Transformer(transformer_model)
        model_path = os.path.join(BASE_DIR, "TRANSFORMER_MODEL_ON_NON_FEATURE_EXTRACTED.pth")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file {model_path} not found")

        model.load_state_dict(torch.load(model_path, map_location=device))
        model.to(device)
        print(f"Model loaded successfully from {model_path}")
    except Exception as e:
        print(f"Error loading model or tokenizer: {e}")
        exit(1)

    # Ví dụ dự đoán
    print("\nTesting predictions:")

    # Test with single URL
    test_urls = ["https://www.google.com/"]
    results = predict_url(test_urls, model, tokenizer)
    for result in results:
        if "error" in result:
            print(f"URL: {result['url']}, Error: {result['error']}")
        else:
            print(f"URL: {result['url']}, Prediction: {result['prediction']}, Probability: {result['probability']:.4f}")

    # Test with multiple URLs
    # print("\nTesting with multiple URLs:")
    # test_urls_multiple = [
    #     "https://www.google.com/",
    #     "https://www.facebook.com/",
    #     "http://suspicious-site.com/login"
    # ]
    # results = predict_url(test_urls_multiple, model, tokenizer)
    # for result in results:
    #     if "error" in result:
    #         print(f"URL: {result['url']}, Error: {result['error']}")
    #     else:
    #         print(f"URL: {result['url']}, Prediction: {result['prediction']}, Probability: {result['probability']:.4f}")
