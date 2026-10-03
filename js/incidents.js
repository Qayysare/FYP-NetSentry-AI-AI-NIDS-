const incidentsBody = document.getElementById("incidents-body");
let currentUser, incidentRows = [], selectedIncident;

const esc = value => String(value ?? "-").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
const date = value => value ? new Date(value).toLocaleString() : "Not recorded";
const set = (id, value) => { document.getElementById(id).innerHTML = value; };

function renderIncidents(rows) {
  incidentRows = rows;
  incidentsBody.innerHTML = rows.map(row => `<tr><td>#${row.ticket_id}</td><td>THR-${row.threat_id}: ${esc(row.attack_type)}</td><td>${esc(row.source_ip)}</td><td>${esc(row.assigned_username || "Unassigned")}</td><td>${esc(row.priority)}</td><td><span class="status ${String(row.status).toLowerCase()}">${esc(row.status)}</span></td><td><button class="action-button" data-response-id="${row.ticket_id}">Respond</button></td></tr>`).join("") || '<tr><td colspan="7">No incidents are assigned to this view.</td></tr>';
  const ticket = new URLSearchParams(location.search).get("ticket");
  if (ticket) {
    const row = rows.find(item => String(item.ticket_id) === ticket);
    if (row) openIncident(row);
  }
}

async function loadIncidents() {
  try { renderIncidents(await apiRequest("/api/incidents")); }
  catch (error) { incidentsBody.innerHTML = `<tr><td colspan="7">${esc(error.message)}</td></tr>`; }
}

async function setupPage() {
  try {
    currentUser = await apiRequest("/api/me");
    if (currentUser.role !== "admin") return;
    document.getElementById("incident-heading").textContent = "Incident Management";
    document.getElementById("create-incident-panel").hidden = false;
    const users = await apiRequest("/api/users");
    document.getElementById("incident-analyst").innerHTML = '<option value="">Unassigned</option>' + users.filter(user => user.role === "analyst" && user.is_active).map(user => `<option value="${user.user_id}">${esc(user.full_name)}</option>`).join("");
  } catch (error) { console.warn(error.message); }
}

function updateReportActions(incident) {
  const available = ["Resolved", "Closed"].includes(incident.status);
  const actions = document.getElementById("incident-report-actions");
  const note = document.getElementById("incident-report-note");
  actions.hidden = !available;
  note.hidden = available;
  if (available) {
    document.getElementById("review-incident-report").textContent = incident.status === "Closed" ? "Review Final Report" : "Review Incident Report";
    document.getElementById("print-incident-report").textContent = incident.status === "Closed" ? "Print Final Report" : "Print Incident Report";
  }
}

function openIncident(incident) {
  const r = incident;
  selectedIncident = incident;
  document.getElementById("response-ticket-id").value = incident.ticket_id;
  document.getElementById("investigation-findings").value = incident.investigation_findings || "";
  document.getElementById("mitigation-taken").value = incident.mitigation_taken || "";
  document.getElementById("response-status").value = ["New", "Assigned"].includes(incident.status) ? "Investigating" : incident.status;
  document.getElementById("verification-remarks").value = incident.verification_remarks || "";
  set("incident-linkage", `Incident ID: INC-${r.ticket_id} | Linked Threat ID: THR-${r.threat_id}<br>Attack Type: ${esc(incident.attack_type)} | Severity: ${esc(incident.severity)} | Confidence: ${esc(incident.confidence_score)}%<br>Source: ${esc(incident.source_ip)} to Destination: ${esc(incident.destination_ip)}<br>Original Detection: ${esc(date(incident.detected_at))}`);
  set("incident-assignment", `Assigned Engineer: ${esc(incident.assigned_username || "Unassigned")}<br>Assigned By: ${esc(incident.assigned_by_username || "Not recorded")}<br>Assignment timestamp: Unavailable (not recorded by the current database schema).`);
  const verified = Boolean(incident.verified_by || incident.verified_username);
  document.getElementById("verification-status").textContent = verified ? "Verified" : "Pending Verification";
  document.getElementById("verified-by").textContent = incident.verified_username || "Not yet verified";
  document.getElementById("verified-at").textContent = date(incident.verified_at);
  document.getElementById("verification-summary-remarks").textContent = incident.verification_remarks || "-";
  const admin = currentUser?.role === "admin";
  document.getElementById("verify-label").hidden = !admin || verified;
  document.getElementById("verification-remarks-label").hidden = !admin || verified;
  updateReportActions(incident);
  document.getElementById("incident-response-panel").hidden = false;
}

function renderReport(report) {
  set("incident-report-identity", `Incident #${report.ticket_id} | Threat #${report.threat_id} | Status: ${report.status} | Verification: ${report.verification_status}`);
  set("incident-report-detection", `Attack Type: ${esc(report.attack_type)}<br>Severity: ${esc(report.severity)}<br>Source: ${esc(report.source_ip)}:${esc(report.source_port || "-")} to ${esc(report.destination_ip)}:${esc(report.destination_port || "-")}<br>Protocol: ${esc(report.protocol || "Not recorded")}<br>Detection Time: ${esc(date(report.detected_at))}`);
  set("incident-report-ai", `Classification: ${esc(report.attack_type)}<br>Confidence: ${esc(report.confidence_score)}%<br>NetSentry AI classification is a model output, not verified ground truth.`);
  set("incident-report-assignment", `Assigned Engineer: ${esc(report.assigned_username || "Unassigned")}<br>Assigned By: ${esc(report.assigned_by_username || "Not recorded")}<br>Assignment Timestamp: Unavailable`);
  set("incident-report-findings", esc(report.investigation_findings || "Not recorded."));
  set("incident-report-mitigation", esc(report.mitigation_taken || "Not recorded."));
  set("incident-report-handler", `Handled By: ${esc(report.handled_username || "Not recorded")}<br>Handled At: ${esc(date(report.handled_at))}<br>Current Status: ${esc(report.status)}`);
  set("incident-report-verification", `Verification Status: ${esc(report.verification_status)}<br>Verified By: ${esc(report.verified_username || "Not yet verified")}<br>Verified At: ${esc(date(report.verified_at))}<br>Verification Remarks: ${esc(report.verification_remarks || "Not recorded.")}`);
  document.getElementById("incident-verifier-signature").textContent = report.verified_username ? "_______________________________" : "Pending Administrator Verification";
  document.getElementById("incident-report-preview").hidden = false;
}

async function reviewIncidentReport(printAfter = false) {
  if (!selectedIncident) return;
  try {
    const report = await apiRequest(`/api/incidents/${selectedIncident.ticket_id}/report`);
    renderReport(report);
    if (printAfter) window.print();
  } catch (error) {
    const messages = { 401: "Authentication is required. Please sign in again.", 403: "You are not authorized to view this incident report.", 404: "The incident report resource was not found. Restart the Flask backend if this feature was just updated.", 409: "This incident report is available only after the ticket is resolved." };
    document.getElementById("response-message").textContent = messages[error.status] || error.message;
  }
}

document.getElementById("create-incident-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const result = await apiRequest("/api/incidents", { method: "POST", body: JSON.stringify({ threat_id: Number(document.getElementById("incident-threat-id").value), assigned_to: document.getElementById("incident-analyst").value || null, priority: document.getElementById("incident-priority").value }) });
    document.getElementById("incident-message").textContent = result.existing ? `Existing active incident INC-${result.ticket_id} opened instead of creating a duplicate.` : "Incident assigned successfully.";
    loadIncidents();
  } catch (error) { document.getElementById("incident-message").textContent = error.message; }
});

incidentsBody.addEventListener("click", event => {
  const button = event.target.closest("button[data-response-id]");
  if (button) openIncident(incidentRows.find(row => String(row.ticket_id) === button.dataset.responseId));
});
document.getElementById("review-incident-report").onclick = () => reviewIncidentReport();
document.getElementById("print-incident-report").onclick = () => reviewIncidentReport(true);
document.getElementById("print-incident-report-header").onclick = () => window.print();
document.getElementById("incident-response-form").addEventListener("submit", async event => {
  event.preventDefault();
  const payload = {
    status: document.getElementById("response-status").value,
    investigation_findings: document.getElementById("investigation-findings").value || null,
    mitigation_taken: document.getElementById("mitigation-taken").value || null,
    verify: document.getElementById("verify-incident").checked,
    verification_remarks: document.getElementById("verification-remarks").value || null,
  };
  try {
    await apiRequest(`/api/incidents/${document.getElementById("response-ticket-id").value}`, { method: "PUT", body: JSON.stringify(payload) });
    await loadIncidents();
  } catch (error) { document.getElementById("response-message").textContent = error.message; }
});

setupPage();
loadIncidents();
