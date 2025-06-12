# Phishing Website Detection Models

## Introduction
This project leverages deep learning models (LSTM, CNN, and Transformer) to detect phishing websites based on URL features. The Jupyter Notebook provides a comprehensive workflow for data analysis, model training, and performance evaluation, including visualizations such as accuracy plots and result tables. Developed on Google Colab, the notebook can be viewed in detail via nbviewer or open .ipynb file using Jupyter Notebook/Colab.

## Summary Results of Each Model

### 1. CNN with Numerical Features
- **Model Architecture**  
  ![CNN Numerical Model](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NUM_MDL.png)
- **Accuracy Graph**  
  ![CNN Numerical Accuracy](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NUM_ACC.png)
- **Loss Graph**  
  ![CNN Numerical Loss](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NUM_LOSS.png)
- **Confusion Matrix**  
  ![CNN Numerical Confusion Matrix](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_CONF_MATRX.png)

### 2. CNN with Non-Numerical Features
- **Model Architecture**  
  ![CNN Non-Numerical Model](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NON_NUM_MDL.png)
- **Accuracy Graph**  
  ![CNN Non-Numerical Accuracy](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NON_NUM_ACC.png)
- **Loss Graph**  
  ![CNN Non-Numerical Loss](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NON_NUM_LOSS.png)
- **Confusion Matrix**  
  ![CNN Non-Numerical Confusion Matrix](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_NON_NUM_CONF_MATRX.png)

### 3. CNN-LSTM with Numerical Features
- **Model Architecture**  
  ![CNN-LSTM Numerical Model](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NUM_MDL.png)
- **Accuracy Graph**  
  ![CNN-LSTM Numerical Accuracy](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NUM_ACC.png)
- **Loss Graph**  
  ![CNN-LSTM Numerical Loss](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NUM_LOSS.png)
- **Confusion Matrix**  
  ![CNN-LSTM Numerical Confusion Matrix](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_CONF_MATRX.png)

### 4. CNN-LSTM with Non-Numerical Features
- **Model Architecture**  
  ![CNN-LSTM Non-Numerical Model](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NON_NUM_MDL.png)
- **Accuracy Graph**  
  ![CNN-LSTM Non-Numerical Accuracy](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NON_NUM_ACC.png)
- **Loss Graph**  
  ![CNN-LSTM Non-Numerical Loss](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NON_NUM_LOSS.png)
- **Confusion Matrix**  
  ![CNN-LSTM Non-Numerical Confusion Matrix](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/CNN_LSTM_NON_NUM_CONF_MATRX.png)

### 5. Transformer’s BERT with Non-Numerical Features
- **Model Architecture**  
    ```
      ==============================================================================================================
      Layer (type:depth-idx)                                       Output Shape              Param #
      ==============================================================================================================
      Transformer                                                  [1, 1]                    --
      ├─BertModel: 1-1                                             [1, 768]                  --
      │    └─BertEmbeddings: 2-1                                   [1, 64, 768]              --
      │    │    └─Embedding: 3-1                                   [1, 64, 768]              23,440,896
      │    │    └─Embedding: 3-2                                   [1, 64, 768]              1,536
      │    │    └─Embedding: 3-3                                   [1, 64, 768]              393,216
      │    │    └─LayerNorm: 3-4                                   [1, 64, 768]              1,536
      │    │    └─Dropout: 3-5                                     [1, 64, 768]              --
      │    └─BertEncoder: 2-2                                      [1, 64, 768]              --
      │    │    └─ModuleList: 3-6                                  --                        85,054,464
      │    └─BertPooler: 2-3                                       [1, 768]                  --
      │    │    └─Linear: 3-7                                      [1, 768]                  590,592
      │    │    └─Tanh: 3-8                                        [1, 768]                  --
      ├─Sequential: 1-2                                            [1, 1]                    --
      │    └─Linear: 2-4                                           [1, 512]                  393,728
      │    └─ReLU: 2-5                                             [1, 512]                  --
      │    └─Dropout: 2-6                                          [1, 512]                  --
      │    └─Linear: 2-7                                           [1, 1]                    513
      │    └─Sigmoid: 2-8                                          [1, 1]                    --
      ==============================================================================================================
      Total params: 109,876,481
      Trainable params: 109,876,481
      Non-trainable params: 0
      Total mult-adds (Units.MEGABYTES): 109.88
      ==============================================================================================================
      Input size (MB): 9.36
      Forward/backward pass size (MB): 53.49
      Params size (MB): 439.51
      Estimated Total Size (MB): 502.36
      ==============================================================================================================
    ```
- **Accuracy Graph**  
  ![BERT Non-Numerical Accuracy](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/TRF_BERT_NON_NUM_ACC.png)
- **Loss Graph**  
  ![BERT Non-Numerical Loss](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/TRF_BERT_NON_NUM_LOSS.png)
- **Confusion Matrix**  
  ![BERT Non-Numerical Confusion Matrix](https://raw.githubusercontent.com/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/main/results/TRF_BERT_NON_NUM_CONF_MATRX.png)

## Set up and Deploy

### Dependencies & Libraries
- **Python Version**: 3.12.1
- **Installation**:
  ```bash
  pip install -r requirements.txt
  ```

### Back-End API
- **Run the API**:
  ```bash
  python ./phishing_api_backend.py
  ```
- **Testing with Postman**:
  - **URL**: `http://localhost:5000/predict`
  - **Body (JSON)**:
    ```json
    {"url": "https://example.com"}
    ```

### Docker Deployment
- **Using Docker Compose**:
  ```bash
  docker-compose up -d
  ```
  (Use this command to build and run the image.)
- **Pull Pre-built Image**:
  ```bash
  docker pull dinhtoan2157/phishing-api:20250611
  ```
- **Visit Docker Hub**:
  - Check the image details at: [https://hub.docker.com/repository/docker/dinhtoan2157/phishing-api/](https://hub.docker.com/repository/docker/dinhtoan2157/phishing-api/)

- **DOWNLOAD TRANSFORMERS's BERT MODEL**
  - Important: Because the TRANSFORMERS's BERT model cant be push via git you must download it seperately here: [transformers-bert-download](https://drive.google.com/file/d/1w5YeG1YkgXCMvLuv-o-VAsndRWEhMMf9/view?usp=sharing)

### Extension
- **Installation**:
  - Open your browser.
  - Import the `phishing-detect-extension` folder to load the extension.
## Resources
- **Dataset**: [Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset/)  
- **Python Script References**: [Mendeley Data](https://data.mendeley.com/datasets/c2gw7fy2j4/3)  
- **Jupyter Notebook**: [View on nbviewer](https://nbviewer.org/github/DinhQuocToan-N21DCAT057/Phishing-Website-Detection-Models/blob/main/LSTM-CNN-Transformer-Phising-Website-Detection.ipynb)
