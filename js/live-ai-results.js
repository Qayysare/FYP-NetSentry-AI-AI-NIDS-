/* Shared rendering and session state for Live Sensor and Manual AI Capture. */
window.createLiveAiView = function createLiveAiView() {
  const displayLimit = 200;
  let cursor = 0;
  let activeSessionIdentity = null;
  const results = new Map();
  const escapeHtml = value => String(value ?? "-").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  const badgeClass = value => String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const confidence = value => Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(2)}%` : "-";
  const element = id => document.getElementById(id);

  function renderRows(flows) {
    const body = element("live-ai-body");
    body.innerHTML = flows.slice(0, displayLimit).map(flow => `<tr><td>${escapeHtml(flow.source_ip)}</td><td>${escapeHtml(flow.destination_ip)}</td><td>${escapeHtml(flow.destination_port)}</td><td>${escapeHtml(flow.protocol)}</td><td><span class="classification ${badgeClass(flow.classification)}">${escapeHtml(flow.classification)}</span></td><td>${confidence(flow.confidence)}</td><td><span class="severity ${badgeClass(flow.severity)}">${escapeHtml(flow.severity)}</span></td><td>${escapeHtml(flow.priority)}</td><td class="wrap-cell">${escapeHtml(flow.recommended_action)}</td></tr>`).join("") || '<tr><td colspan="9">No completed AI flows were returned.</td></tr>';
    const limit = element("live-ai-row-limit");
    limit.hidden = flows.length <= displayLimit;
    limit.textContent = `Showing the latest ${displayLimit} completed AI flows.`;
  }

  function resetForNewSession(identity = null) {
    activeSessionIdentity = identity;
    cursor = 0;
    results.clear();
    renderRows([]);
    ["live-packet-count", "live-active-flow-count", "live-flow-count", "live-prediction-count", "live-stored-threat-count"].forEach(id => { const target = element(id); if (target) target.textContent = "0"; });
    const note = element("live-session-results-note");
    if (note) note.textContent = "Waiting for completed flows from the current monitoring session.";
  }

  function syncSession(status) {
    const identity = status?.started_at == null ? null : String(status.started_at);
    if (!identity || identity === activeSessionIdentity) return false;
    resetForNewSession(identity);
    return true;
  }

  function addResults(flows) {
    flows.forEach(flow => {
      const id = Number(flow.result_id);
      if (Number.isFinite(id)) { results.set(id, flow); cursor = Math.max(cursor, id); }
    });
    while (results.size > displayLimit) results.delete(Math.min(...results.keys()));
  }

  function render(status) {
    addResults(status.ai_flows || []);
    const flows = Array.from(results.values()).sort((left, right) => right.result_id - left.result_id);
    const packets = status.packets_captured ?? status.captured_packets ?? status.packet_count ?? 0;
    element("live-packet-count").textContent = packets;
    element("live-active-flow-count").textContent = status.active_flows ?? 0;
    element("live-flow-count").textContent = status.completed_flows ?? status.ai_flow_count ?? 0;
    element("live-prediction-count").textContent = status.prediction_count ?? flows.length;
    element("live-malicious-count").textContent = `${status.malicious_flow_count ?? 0} threats detected`;
    element("live-stored-threat-count").textContent = status.stored_threat_count ?? 0;
    element("live-duplicates").textContent = `${status.duplicate_suppressed_count ?? 0} duplicates suppressed`;
    const note = element("live-session-results-note");
    if (note) note.textContent = status.running ? "Current completed-flow model results." : (status.started_at || flows.length || Number(status.completed_flows || status.ai_flow_count) ? "Results from the last completed monitoring session." : "No completed monitoring session data is available.");
    element("live-capture-summary").hidden = false;
    element("live-ai-results").hidden = !(status.running || flows.length || Number(status.completed_flows || status.ai_flow_count));
    element("live-benign-message").hidden = Number(status.malicious_flow_count || 0) !== 0 || !flows.length;
    element("view-threat-alerts").hidden = Number(status.malicious_flow_count || 0) === 0;
    renderRows(flows);
  }

  return { get cursor() { return cursor; }, resetForNewSession, syncSession, render };
};
