const manualView = createLiveAiView();
const manualMessage = document.getElementById("manual-message");
const manualInterface = document.getElementById("capture-interface");
const manualStart = document.getElementById("start-capture");
const manualStop = document.getElementById("stop-capture");
let manualTimer, captureControlAllowed = false, manualUpdating = false, manualUpdateVersion = 0;
const escapeManual = value => String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);

function showManualMessage(message, success = false) { manualMessage.className = success ? "form-message success" : "form-message"; manualMessage.textContent = message; }
function setManualControls(status) {
  const autonomousConflict = status.running && status.mode === "autonomous";
  const manualRunning = status.running && status.mode === "manual";
  manualInterface.disabled = !captureControlAllowed || autonomousConflict || manualRunning;
  manualStart.disabled = !captureControlAllowed || autonomousConflict || manualRunning;
  manualStop.disabled = !captureControlAllowed || !status.running;
  document.getElementById("manual-status").textContent = autonomousConflict ? "Autonomous sensor active" : manualRunning ? "Manual AI capture active" : "Monitoring stopped";
  document.getElementById("monitoring-mode").textContent = status.running ? status.mode === "autonomous" ? "Autonomous Sensor" : "Manual AI Capture" : "—";
  document.getElementById("monitoring-interface").textContent = status.running ? status.interface_name || status.interface || "Configured sensor" : "—";
  document.getElementById("live-session-state").textContent = status.running ? "Current monitoring session" : (status.started_at || Number(status.completed_flows || status.ai_flow_count) ? "Last completed monitoring session" : "No completed monitoring session available");
  if (autonomousConflict) showManualMessage("Autonomous sensor monitoring is currently active. Stop the current sensor session before starting a manual capture.");
}
async function loadManualInterfaces() { try { const interfaces = await apiRequest("/api/capture/interfaces"); manualInterface.innerHTML = '<option value="">Select authorised capture interface</option>' + interfaces.map(item => `<option value="${escapeManual(item.id)}">${escapeManual(item.id)}. ${escapeManual(item.name)}</option>`).join(""); } catch (error) { showManualMessage(error.message || "Capture interfaces could not be loaded."); } }
async function updateManualStatus() {
  if (manualUpdating) return;
  manualUpdating = true;
  const requestVersion = manualUpdateVersion;
  try {
    let status = await apiRequest(`/api/capture/status?after=${manualView.cursor}`);
    if (requestVersion !== manualUpdateVersion) return;
    if (manualView.syncSession(status)) { status = await apiRequest("/api/capture/status?after=0"); if (requestVersion !== manualUpdateVersion) return; }
    manualView.render(status); setManualControls(status);
  } catch (error) { showManualMessage(error.message || "Capture status could not be loaded."); }
  finally { manualUpdating = false; }
}
manualStart.onclick = async () => {
  if (!manualInterface.value) return showManualMessage("Select an authorised capture interface first.");
  manualUpdateVersion += 1;
  manualStart.disabled = true; document.getElementById("manual-status").textContent = "Starting manual AI capture"; showManualMessage("Starting manual AI capture...");
  try { const status = await apiRequest("/api/capture/start", { method: "POST", body: JSON.stringify({ interface_id: manualInterface.value }) }); manualView.syncSession(status); manualView.render(status); setManualControls(status); showManualMessage("Manual AI capture is active. Completed flows are analysed by the existing model.", true); }
  catch (error) { showManualMessage(error.message || "Manual AI capture could not be started."); await updateManualStatus(); }
};
manualStop.onclick = async () => {
  manualUpdateVersion += 1;
  manualStop.disabled = true; document.getElementById("manual-status").textContent = "Stopping manual AI capture"; showManualMessage("Stopping capture and flushing remaining eligible flows...");
  try { const status = await apiRequest("/api/capture/stop", { method: "POST" }); manualView.render(status); setManualControls(status); showManualMessage("Manual AI capture stopped cleanly. Completed results below are historical.", true); }
  catch (error) { showManualMessage(error.message || "Manual AI capture could not be stopped."); await updateManualStatus(); }
};
window.aiNidsUserReady?.then(() => { captureControlAllowed = window.aiNidsCurrentUser?.role === "admin"; if (!captureControlAllowed) showManualMessage("Capture controls require an administrator account. Live status and AI flow results remain available."); updateManualStatus(); });
loadManualInterfaces(); updateManualStatus(); manualTimer = setInterval(updateManualStatus, 3000); addEventListener("beforeunload", () => clearInterval(manualTimer));
