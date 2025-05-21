// Function to validate URL
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Auto-fill current tab URL when popup opens
chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const currentTab = tabs[0];
    if (currentTab?.url && currentTab.url.startsWith('http')) {
        document.getElementById("urlInput").value = currentTab.url;
    }
});

document.getElementById("checkBtn").addEventListener("click", () => {
    const url = document.getElementById("urlInput").value.trim();
    const loader = document.getElementById("loader");
    const resultDiv = document.getElementById("result");
    const checkBtn = document.getElementById("checkBtn");
    
    if (!url) {
        resultDiv.innerHTML = `
            <div class="result-item">
                <i class="fas fa-exclamation-circle error-icon"></i>
                Please enter a URL
            </div>`;
        return;
    }

    if (!isValidUrl(url)) {
        resultDiv.innerHTML = `
            <div class="result-item">
                <i class="fas fa-exclamation-circle error-icon"></i>
                Please enter a valid URL (e.g., https://www.example.com)
            </div>`;
        return;
    }
      // Disable button and show loader
    checkBtn.disabled = true;
    loader.style.display = "block";
    resultDiv.innerHTML = "";
      // Send URL directly to background script for checking
    chrome.runtime.sendMessage({ action: "checkUrl", url: url })
    .then(data => {
      if (data.error) {
        throw new Error(data.error);
      }

      const models = [
        { name: "CNN-LSTM Numerical", data: data?.cnn_lstm_model_numerical },
        { name: "CNN-LSTM Text", data: data?.cnn_lstm_model_text },
        { name: "CNN Numerical", data: data?.cnn_model_numerical },
        { name: "CNN Text", data: data?.cnn_model_text }
      ];

      const results = models.map(model => {
        if (!model.data || typeof model.data.label === 'undefined' || typeof model.data.confidence === 'undefined') {
          return `<div class="result-item">
            <i class="fas fa-exclamation-circle error-icon"></i>
            ${model.name}: No data available
          </div>`;
        }

        const label = model.data.label;
        const conf = (model.data.confidence * 100).toFixed(2);
        const isPhishing = label === 1;
        
        return `<div class="result-item">
          <i class="fas ${isPhishing ? 'fa-exclamation-triangle warning-icon' : 'fa-info-circle safe-icon'}"></i>
          ${model.name}: ${isPhishing ? "Phishing" : "Safe"} (Confidence: ${conf}%)
        </div>`;
      });

      resultDiv.innerHTML = results.join("");
    })
    .catch(err => {
      let errorMessage = "Error: ";
      if (err.message.includes("API server is not running")) {
        errorMessage += "The prediction server is not running. Please make sure it's started.";
      } else if (err.message.includes("Failed to fetch")) {
        errorMessage += "Could not connect to the server. Please check your connection.";
      } else {
        errorMessage += err.message || "Failed to fetch result";
      }

      resultDiv.innerHTML = `
        <div class="result-item">
          <i class="fas fa-times-circle error-icon"></i>
          ${errorMessage}
        </div>`;
      console.error('Error details:', err);
    })
    .finally(() => {
      // Re-enable button and hide loader
      checkBtn.disabled = false;
      loader.style.display = "none";
    });
  });
  