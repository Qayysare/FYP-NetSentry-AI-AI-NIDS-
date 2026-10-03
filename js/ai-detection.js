const analysisForm = document.getElementById("ai-analysis-form");
const captureFile = document.getElementById("capture-file");
const analyzeButton = document.getElementById("analyze-button");
const analysisState = document.getElementById("analysis-state");
const analysisMessage = document.getElementById("analysis-message");
const analysisResults = document.getElementById("analysis-results");
const validationButton = document.getElementById("run-validation-button");
const validationMessage = document.getElementById("validation-message");
const validationResults = document.getElementById("validation-results");
const validationResultsBody = document.getElementById("validation-results-body");

const classLabels = ["BENIGN", "DDoS", "FTP-Patator", "PortScan", "SSH-Patator"];
const severityLabels = ["Informational", "Medium", "High", "Critical"];

function escapeHtml(value) {
  return String(value ?? "-").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function formatConfidence(value) {
  const probability = Number(value);
  return Number.isFinite(probability) ? `${(probability * 100).toFixed(2)}%` : "-";
}

function badgeClass(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function setAnalysisState(state, message) {
  analysisState.className = `analysis-state ${state}`;
  const icon = state === "loading" ? "fa-spinner fa-spin" : state === "completed" ? "fa-circle-check" : state === "error" ? "fa-circle-exclamation" : "fa-circle";
  analysisState.innerHTML = `<i class="fa-solid ${icon}"></i> ${escapeHtml(message)}`;
}

function renderDistribution(elementId, labels, values) {
  document.getElementById(elementId).innerHTML = labels.map(label => `<div><span>${escapeHtml(label)}</span><strong>${Number(values?.[label] || 0)}</strong></div>`).join("");
}

function renderPredictions(predictions) {
  const body = document.getElementById("predictions-body");
  body.innerHTML = predictions.map(prediction => `<tr>
    <td>${escapeHtml(prediction.source_ip)}${prediction.source_port != null ? `:${escapeHtml(prediction.source_port)}` : ""}</td>
    <td>${escapeHtml(prediction.destination_ip)}${prediction.destination_port != null ? `:${escapeHtml(prediction.destination_port)}` : ""}</td>
    <td>${escapeHtml(prediction.protocol)}</td>
    <td><span class="classification ${badgeClass(prediction.classification)}">${escapeHtml(prediction.classification)}</span></td>
    <td>${formatConfidence(prediction.confidence)}</td>
    <td><span class="severity ${badgeClass(prediction.severity)}">${escapeHtml(prediction.severity)}</span></td>
    <td>${escapeHtml(prediction.priority)}</td>
    <td class="wrap-cell">${escapeHtml(prediction.recommended_action)}</td>
  </tr>`).join("") || '<tr><td colspan="8">No completed flows were returned for this capture.</td></tr>';
}

function renderResults(data) {
  document.getElementById("result-filename").textContent = data.filename || "-";
  document.getElementById("result-packets").textContent = data.packet_count ?? 0;
  document.getElementById("result-flows").textContent = data.flow_count ?? 0;
  document.getElementById("result-predictions").textContent = data.prediction_count ?? 0;
  document.getElementById("result-malicious").textContent = `${data.malicious_flow_count ?? 0} malicious flows`;
  document.getElementById("result-attention").textContent = data.requires_attention_count ?? 0;
  document.getElementById("result-storage").textContent = `${data.stored_threat_count ?? 0} stored threats${data.duplicate_suppressed_count ? `, ${data.duplicate_suppressed_count} duplicates suppressed` : ""}`;
  document.getElementById("benign-message").hidden = Number(data.malicious_flow_count || 0) !== 0;
  renderDistribution("class-summary", classLabels, data.summary);
  renderDistribution("severity-summary", severityLabels, data.severity_summary);
  renderPredictions(data.predictions || []);
  analysisResults.hidden = false;
}

function renderValidationResults(data) {
  validationResultsBody.innerHTML = (data.classes || []).map(result => {
    const fixed = result.fixed_sample || {};
    const representative = result.representative_pass ? "PASS" : "FAIL";
    return `<tr>
      <td><span class="classification ${badgeClass(result.class_name)}">${escapeHtml(result.class_name)}</span></td>
      <td>${escapeHtml(result.expected_label)}</td>
      <td>${escapeHtml(result.predicted_label)}</td>
      <td>${formatConfidence(result.confidence)}</td>
      <td><span class="severity ${badgeClass(result.severity)}">${escapeHtml(result.severity)}</span></td>
      <td>${escapeHtml(result.priority)}</td>
      <td class="wrap-cell">${escapeHtml(result.recommended_action)}</td>
      <td>${representative} (${Number(result.rows_examined || 0)} row${Number(result.rows_examined || 0) === 1 ? "" : "s"} examined)</td>
      <td>${Number(fixed.correct_count || 0)}/${Number(fixed.sample_count || 0)}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="9">No held-out validation results were returned.</td></tr>';
  validationResults.hidden = false;
}

analysisForm.addEventListener("submit", async event => {
  event.preventDefault();
  const file = captureFile.files[0];
  if (!file) {
    analysisMessage.textContent = "Choose a .pcap or .pcapng file first.";
    setAnalysisState("error", "A capture file is required.");
    return;
  }
  if (!/\.pcapng?$/i.test(file.name)) {
    analysisMessage.textContent = "Only .pcap and .pcapng files are supported.";
    setAnalysisState("error", "Unsupported capture format.");
    return;
  }

  analyzeButton.disabled = true;
  analysisMessage.textContent = "";
  setAnalysisState("loading", "Uploading and analysing the capture. This may take a moment.");
  try {
    const formData = new FormData();
    formData.append("capture_file", file);
    const data = await apiRequest("/api/ai/analyze-pcap", { method: "POST", body: formData });
    renderResults(data);
    setAnalysisState("completed", "Analysis completed successfully.");
  } catch (error) {
    analysisMessage.textContent = error.message || "The analysis could not be completed.";
    setAnalysisState("error", "Analysis could not be completed. Review the message below and try again.");
  } finally {
    analyzeButton.disabled = false;
  }
});

validationButton.addEventListener("click", async () => {
  validationButton.disabled = true;
  validationMessage.textContent = "Loading held-out validation results...";
  try {
    const data = await apiRequest("/api/ai/validation-summary");
    renderValidationResults(data);
    validationMessage.textContent = `Validation completed using ${data.feature_count} shared runtime features.`;
  } catch (error) {
    validationMessage.textContent = error.message || "Held-out validation could not be completed.";
  } finally {
    validationButton.disabled = false;
  }
});
