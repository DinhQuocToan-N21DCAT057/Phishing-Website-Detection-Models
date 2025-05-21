// Cache for storing previous results
const resultCache = new Map();

// Function to check URL against the API
async function checkUrl(url) {
    // Check cache first
    if (resultCache.has(url)) {
        return resultCache.get(url);
    }

    try {
        const response = await fetch("http://localhost:5000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        // Validate the response data
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid response format');
        }

        // Check if the response has the expected model results
        const requiredModels = [
            'cnn_lstm_model_numerical',
            'cnn_lstm_model_text',
            'cnn_model_numerical',
            'cnn_model_text'
        ];

        for (const model of requiredModels) {
            if (!data[model] || !('label' in data[model]) || !('confidence' in data[model])) {
                throw new Error(`Missing or invalid ${model} data`);
            }
        }
        
        // Cache the result
        resultCache.set(url, data);
        
        // Clear old cache entries if cache gets too large
        if (resultCache.size > 100) {
            const firstKey = resultCache.keys().next().value;
            resultCache.delete(firstKey);
        }

        return data;
    } catch (error) {
        console.error('Error checking URL:', error);
        throw error;
    }
}

// Listen for messages from popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkUrl") {
        checkUrl(request.url)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ error: error.message }));
        return true; // Will respond asynchronously
    }
});

// Optional: Listen for tab updates to preload results
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab.url && tab.url.startsWith('http')) {
            checkUrl(tab.url).catch(console.error);
        }
    } catch (error) {
        console.error('Error pre-checking URL:', error);
    }
});