const API_BASE = "https://phishingdetect-phish-aegis-api.hf.space";

const scanBtn = document.getElementById("scanBtn");
const urlText = document.getElementById("urlText");
const predictionText = document.getElementById("predictionText");
const finalText = document.getElementById("finalText");

function getPrediction(data) {
  return data.url_prediction || data.prediction || "-";
}

function getFinalDecision(data) {
  return data.final_decision || data.url_prediction || data.prediction || "Unknown";
}

scanBtn.addEventListener("click", async () => {
  predictionText.textContent = "Scanning...";
  finalText.textContent = "-";
  predictionText.className = "";
  finalText.className = "";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const currentUrl = tabs[0].url;
    urlText.textContent = currentUrl;

    const response = await fetch(`${API_BASE}/predict_url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "API request failed");
    }

    const prediction = getPrediction(data);
    const finalDecision = getFinalDecision(data);

    predictionText.textContent = prediction;
    finalText.textContent = finalDecision;

    if (finalDecision.toLowerCase().includes("phishing")) {
      predictionText.className = "high";
      finalText.className = "high";
    } else {
      predictionText.className = "low";
      finalText.className = "low";
    }

  } catch (error) {
    predictionText.textContent = "Error: API not reachable";
    finalText.textContent = error.message;
    predictionText.className = "high";
    finalText.className = "high";
  }
});