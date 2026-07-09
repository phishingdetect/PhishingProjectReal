 const tabButtons = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");

const loadingBox = document.getElementById("loadingBox");
const resultBox = document.getElementById("resultBox");

const riskTitle = document.getElementById("riskTitle");
const riskPercent = document.getElementById("riskPercent");
const riskText = document.getElementById("riskText");
const gaugeFill = document.getElementById("gaugeFill");

const resultChannel = document.getElementById("resultChannel");
const resultPrediction = document.getElementById("resultPrediction");
const resultConfidence = document.getElementById("resultConfidence");
const resultFinal = document.getElementById("resultFinal");
const resultUrls = document.getElementById("resultUrls");
const resultUrlAnalysis = document.getElementById("resultUrlAnalysis");
const resultRawText = document.getElementById("resultRawText");

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    tabButtons.forEach((btn) => btn.classList.remove("active"));
    tabContents.forEach((tab) => tab.classList.remove("active"));

    button.classList.add("active");
    document.getElementById(button.dataset.tab).classList.add("active");
  });
});

function showLoading() {
  loadingBox.classList.add("show");
}

function hideLoading() {
  loadingBox.classList.remove("show");
}

function safeJson(value) {
  if (!value || (Array.isArray(value) && value.length === 0)) {
    return "-";
  }

  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value, null, 2);
}

function getFinalDecision(data) {
  return (
    data.final_decision ||
    data.url_prediction ||
    data.email_prediction ||
    data.sms_prediction ||
    data.prediction ||
    "Unknown"
  );
}

function getPrediction(data) {
  return (
    data.email_prediction ||
    data.sms_prediction ||
    data.url_prediction ||
    data.prediction ||
    "-"
  );
}

function getConfidence(data) {
  if (data.email_confidence !== undefined && data.email_confidence !== null) {
    return `${data.email_confidence}%`;
  }

  if (data.sms_confidence !== undefined && data.sms_confidence !== null) {
    return `${data.sms_confidence}%`;
  }

  if (data.confidence !== undefined && data.confidence !== null) {
    return `${data.confidence}%`;
  }

  return "-";
}

function getRiskScore(data) {
  const decision = getFinalDecision(data).toLowerCase();

  let confidence = 0;

  if (data.email_confidence !== undefined && data.email_confidence !== null) {
    confidence = Number(data.email_confidence);
  } else if (data.sms_confidence !== undefined && data.sms_confidence !== null) {
    confidence = Number(data.sms_confidence);
  } else if (data.confidence !== undefined && data.confidence !== null) {
    confidence = Number(data.confidence);
  }

  if (decision.includes("phishing") || decision.includes("smishing")) {
    return confidence > 0 ? Math.max(70, Math.min(99, Math.round(confidence))) : 92;
  }

  if (decision.includes("safe")) {
    return confidence > 0 ? Math.max(1, Math.min(30, 100 - Math.round(confidence))) : 12;
  }

  if (decision.includes("suspicious")) {
    return 55;
  }

  return 40;
}

function updateGauge(score) {
  const risk = Math.max(0, Math.min(100, score));
  riskPercent.textContent = `${risk}%`;

  let color = "#35d399";
  let label = "Low Risk";

  if (risk >= 70) {
    color = "#ff4d6d";
    label = "High Risk";
  } else if (risk >= 40) {
    color = "#ffb547";
    label = "Medium Risk";
  }

  riskText.textContent = label;
  riskTitle.textContent = label;

  gaugeFill.style.background = `conic-gradient(from 220deg, ${color} 0deg ${risk * 2.3}deg, transparent ${risk * 2.3}deg 360deg)`;
}

function updateResult(data, channelName) {
  const finalDecision = getFinalDecision(data);
  const riskScore = getRiskScore(data);

  updateGauge(riskScore);


resultChannel.textContent = channelName || data.channel || "-";
resultPrediction.textContent = getPrediction(data);
resultConfidence.textContent = getConfidence(data);
resultFinal.textContent = finalDecision;

/* URLs */
if (Array.isArray(data.extracted_urls)) {
  resultUrls.textContent = data.extracted_urls.join("\n");
} else {
  resultUrls.textContent = data.extracted_urls || "-";
}

/* URL Analysis */
if (Array.isArray(data.url_analysis)) {
  resultUrlAnalysis.textContent = data.url_analysis
    .map(item => {
      const url = item.url || "-";
      const prediction = item.prediction || "-";
      return `${url} → ${prediction}`;
    })
    .join("\n");
} else {
  resultUrlAnalysis.textContent = data.url_analysis || "-";
}

/* OCR Text */
resultRawText.textContent =
  data.extracted_ocr_text ||
  data.raw_ocr_text ||
  data.input_text ||
  data.message ||
  "-";
  resultBox.classList.remove("hidden");
  resultBox.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function handleResponse(response) {
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

document.getElementById("urlForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const url = document.getElementById("urlInput").value.trim();

  if (!url) {
    alert("Please enter a URL.");
    return;
  }

  showLoading();

  try {
    const response = await fetch("/predict_url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await handleResponse(response);
    updateResult(data, "URL");
  } catch (error) {
    alert(error.message || "Error analyzing URL.");
  } finally {
    hideLoading();
  }
});

document.getElementById("emailForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const emailText = document.getElementById("emailInput").value.trim();

  if (!emailText) {
    alert("Please paste email text.");
    return;
  }

  showLoading();

  try {
    const response = await fetch("/predict_email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email_text: emailText })
    });

    const data = await handleResponse(response);
    updateResult(data, "Email");
  } catch (error) {
    alert(error.message || "Error analyzing email.");
  } finally {
    hideLoading();
  }
});

document.getElementById("smsForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const smsText = document.getElementById("smsInput").value.trim();

  if (!smsText) {
    alert("Please paste SMS text.");
    return;
  }

  showLoading();

  try {
    const response = await fetch("/predict_sms", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ sms_text: smsText })
    });

    const data = await handleResponse(response);
    updateResult(data, "SMS");
  } catch (error) {
    alert(error.message || "Error analyzing SMS.");
  } finally {
    hideLoading();
  }
});

document.getElementById("imageForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const imageFile = document.getElementById("imageInput").files[0];

  if (!imageFile) {
    alert("Please select an image.");
    return;
  }

  const formData = new FormData();
  formData.append("email_image", imageFile);

  showLoading();

  try {
    const response = await fetch("/predict_image_email", {
      method: "POST",
      body: formData
    });

    const data = await handleResponse(response);
    updateResult(data, "Image Email");
  } catch (error) {
    alert(error.message || "Error analyzing image email.");
  } finally {
    hideLoading();
  }
});