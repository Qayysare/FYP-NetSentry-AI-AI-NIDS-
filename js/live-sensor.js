const sensorView = createLiveAiView();
const sensorMessage = document.getElementById("sensor-message");
const stopSensor = document.getElementById("stop-sensor");
const CLASS_COLORS = { BENIGN: "#37c88b", PortScan: "#f4ad42", DDoS: "#f06170", "SSH-Patator": "#ff9f43", "FTP-Patator": "#9b8cff" };
const CLASS_ORDER = Object.keys(CLASS_COLORS);
let sensorTimer, classificationChart, severityChart, captureControlAllowed = false, sensorUpdating = false, sensorUpdateVersion = 0;
const buckets = new Map();

function initCharts() {
  const options = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "top", labels: { color: "#cbd5e1" } }, tooltip: { backgroundColor: "#0d1727" } }, scales: { x: { grid: { color: "#26354b" }, ticks: { color: "#9cacbf" } }, y: { beginAtZero: true, grid: { color: "#26354b" }, ticks: { color: "#9cacbf", precision: 0 } } } };
  classificationChart = new Chart(document.getElementById("live-classification-chart"), { type: "line", data: { labels: [], datasets: CLASS_ORDER.map(label => ({ label, data: [], borderColor: CLASS_COLORS[label], backgroundColor: `${CLASS_COLORS[label]}22`, borderWidth: 2, pointRadius: 3, pointHoverRadius: 6, fill: true, tension: .35 })) }, options });
  severityChart = new Chart(document.getElementById("live-severity-chart"), { type: "bar", data: { labels: [], datasets: [{ label: "Predictions", data: [], backgroundColor: ["#42a5f5", "#f4ad42", "#ff9f43", "#f06170"], borderRadius: 5 }] }, options });
}
function resetSensorCharts() { buckets.clear(); classificationChart.data.labels = []; classificationChart.data.datasets.forEach(dataset => dataset.data = []); classificationChart.update(); severityChart.data.labels = []; severityChart.data.datasets[0].data = []; severityChart.update(); }
function updateCharts(status) {
  (status.ai_flows || []).forEach(flow => { const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); const bucket = buckets.get(time) || Object.fromEntries(CLASS_ORDER.map(classification => [classification, 0])); bucket[flow.classification] = (bucket[flow.classification] || 0) + 1; buckets.set(time, bucket); });
  const rows = Array.from(buckets.entries()).slice(-20);
  classificationChart.data.labels = rows.map(row => row[0]); classificationChart.data.datasets.forEach(dataset => dataset.data = rows.map(row => row[1][dataset.label] || 0)); classificationChart.update();
  const severity = status.severity_summary || {}; severityChart.data.labels = Object.keys(severity); severityChart.data.datasets[0].data = Object.values(severity); severityChart.update();
  document.getElementById("live-activity-empty").hidden = rows.length > 0; document.getElementById("live-sensor-charts").hidden = false;
}
function setState(status) {
  const running = Boolean(status.running);
  stopSensor.disabled = !captureControlAllowed || !running;
  document.getElementById("sensor-status").textContent = running ? "● SENSOR ACTIVE" : "● SENSOR STOPPED";
  document.getElementById("monitoring-interface").textContent = running ? status.interface_name || status.interface || "Configured sensor" : "—";
  document.getElementById("monitoring-mode").textContent = running ? status.mode === "autonomous" ? "Autonomous Sensor" : "Manual AI Capture" : "—";
  document.getElementById("live-session-state").textContent = running ? "Current monitoring session" : (status.started_at || Number(status.completed_flows || status.ai_flow_count) ? "Last completed monitoring session" : "No completed monitoring session available");
  if (status.last_error) sensorMessage.textContent = status.last_error;
}
async function update() {
  if (sensorUpdating) return;
  sensorUpdating = true;
  const requestVersion = sensorUpdateVersion;
  try {
    let status = await apiRequest(`/api/capture/status?after=${sensorView.cursor}`);
    if (requestVersion !== sensorUpdateVersion) return;
    if (sensorView.syncSession(status)) { resetSensorCharts(); status = await apiRequest("/api/capture/status?after=0"); if (requestVersion !== sensorUpdateVersion) return; }
    sensorView.render(status); setState(status); updateCharts(status);
  } catch (error) { sensorMessage.textContent = error.message; }
  finally { sensorUpdating = false; }
}
stopSensor.onclick = async () => { if (!captureControlAllowed) return; sensorUpdateVersion += 1; try { const status = await apiRequest("/api/capture/stop", { method: "POST" }); sensorView.render(status); setState(status); updateCharts(status); } catch (error) { sensorMessage.textContent = error.message; } };
window.aiNidsUserReady?.then(() => { captureControlAllowed = window.aiNidsCurrentUser?.role === "admin"; if (!captureControlAllowed) sensorMessage.textContent = "Sensor controls require an administrator account. Live sensor status remains available."; update(); });
initCharts(); update(); sensorTimer = setInterval(update, 3000); addEventListener("beforeunload", () => clearInterval(sensorTimer));
