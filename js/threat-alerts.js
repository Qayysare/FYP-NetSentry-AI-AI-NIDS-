const alertsBody = document.getElementById("alerts-body");
const alertsMessage = document.getElementById("alerts-message");
const alertDetail = document.getElementById("alert-detail");
let alertRows = [];

function escapeHtml(value) {
  return String(value ?? "-").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function formatConfidence(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return "-";
  return `${(score <= 1 ? score * 100 : score).toFixed(2)}%`;
}

function badgeClass(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function renderAlerts(rows) {
  alertsBody.innerHTML = rows.map(row => `<tr><td>THR-${String(row.threat_id).padStart(4, "0")}</td><td><span class="classification ${badgeClass(row.attack_type)}">${escapeHtml(row.attack_type)}</span></td><td><span class="severity ${badgeClass(row.severity)}">${escapeHtml(row.severity)}</span></td><td>${escapeHtml(row.source_ip)}</td><td>${escapeHtml(row.destination_ip)}</td><td>${formatConfidence(row.confidence_score)}</td><td>${escapeHtml(row.priority || "Policy unavailable")}</td><td>${formatDate(row.detected_at)}</td><td><span class="status ${badgeClass(row.status)}">${escapeHtml(row.status)}</span></td><td><button class="action-button" data-id="${escapeHtml(row.threat_id)}">Review</button></td></tr>`).join("") || '<tr><td colspan="10">No persisted threat alerts match this filter.</td></tr>';
}

function filterAlerts() {
  const severity = document.getElementById("severity-filter").value;
  alertDetail.hidden = true;
  renderAlerts(alertRows.filter(row => !severity || row.severity === severity));
}

async function loadThreats() {
  alertsMessage.textContent = "";
  try {
    alertRows = await apiRequest("/api/threats");
    filterAlerts();
  } catch (error) {
    alertRows = [];
    renderAlerts([]);
    alertsMessage.textContent = error.message || "Threat alerts could not be loaded.";
  }
}

document.getElementById("severity-filter").addEventListener("change", filterAlerts);
alertsBody.addEventListener("click", async event => {
  const button = event.target.closest("button[data-id]");
  if (!button) return;
  const row = alertRows.find(item => String(item.threat_id) === button.dataset.id);
  if (!row) return;
  alertDetail.hidden = false;
  try {
    const incidents = await apiRequest(`/api/threats/${row.threat_id}/incidents`);
    const links = incidents.length
      ? incidents.map(item => `<a href="incidents.html?ticket=${item.ticket_id}">Incident INC-${item.ticket_id} (${escapeHtml(item.status)})</a>`).join(" · ")
      : "No incident is currently linked to this threat.";
    alertDetail.innerHTML = `<strong>Threat ID: THR-${row.threat_id}</strong><br>${row.recommended_action ? `Recommended action: ${escapeHtml(row.recommended_action)}${row.reason ? ` ${escapeHtml(row.reason)}` : ""}` : "No Stage 4 policy guidance is available for this existing alert type."}<br>Linked incident: ${links}`;
  } catch (error) {
    alertDetail.textContent = error.message || "Linked incident information could not be loaded.";
  }
});

loadThreats();
