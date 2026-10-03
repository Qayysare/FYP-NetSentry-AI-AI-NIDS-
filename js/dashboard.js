const threatTable = document.getElementById("recent-threats-body");
const dashboardMessage = document.getElementById("dashboard-message");
let networkChart;
let overviewChart;
const chartOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: "#26354b" }, ticks: { color: "#9cacbf" } }, y: { beginAtZero: true, grid: { color: "#26354b" }, ticks: { color: "#9cacbf" } } } };

function escapeHtml(value) { return String(value ?? "-").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]); }
function severityClass(value) { return String(value || "medium").toLowerCase(); }
function statusClass(value) { return String(value || "new").toLowerCase().replace(" ", "-"); }
function formatDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString(); }
function formatConfidence(value) { const score = Number(value); return Number.isFinite(score) ? `${(score * 100).toFixed(1)}%` : "-"; }
function setText(id, value) { document.getElementById(id).textContent = value; }

function renderThreats(rows, message = "No recent threats recorded.") { threatTable.innerHTML = rows.map(item => `<tr><td>${formatDate(item.detected_at)}</td><td>${escapeHtml(item.attack_type)}</td><td><span class="severity ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td><td>${formatConfidence(item.confidence_score)}</td><td><span class="status ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td></tr>`).join("") || `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`; }
function initialiseCharts() { networkChart = new Chart(document.getElementById("networkActivityChart"), { type: "line", data: { labels: [], datasets: [{ label: "Recorded traffic bytes", data: [], borderColor: "#42a5f5", backgroundColor: "#42a5f52b", fill: true, tension: .35 }] }, options: chartOptions }); overviewChart = new Chart(document.getElementById("threatOverviewChart"), { type: "doughnut", data: { labels: [], datasets: [{ data: [], backgroundColor: ["#37c88b", "#f4ad42", "#f06170"], borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: false } } } }); }
function updateNetworkChart(activity) { networkChart.data.labels = activity.map(item => item.label); networkChart.data.datasets[0].data = activity.map(item => item.value); networkChart.update(); const empty = document.getElementById("network-activity-empty"); empty.hidden = activity.length > 0; if (!activity.length) empty.textContent = "No network activity available for this period."; }
function updateOverviewChart(overview) { const counts = Object.fromEntries(overview.map(item => [item.label, item.value])); const labels = ["Normal", "Suspicious", "Malicious"]; const values = labels.map(label => counts[label] || 0); overviewChart.data.labels = labels; overviewChart.data.datasets[0].data = values; overviewChart.update(); const empty = document.getElementById("threat-overview-empty"); empty.hidden = values.some(value => value > 0); if (!values.some(value => value > 0)) empty.textContent = "No persisted threat overview is available."; }
function applyMonitoringState(status) { const running = Boolean(status.running); setText("stat-monitoring", running ? "ACTIVE" : "STOPPED"); setText("stat-monitoring-detail", running ? `Interface: ${status.interface_name || status.interface || "configured sensor"}` : status.last_error || "Monitoring is currently stopped"); document.getElementById("network-activity-context").textContent = running ? "Recorded traffic volume; the sensor is currently active." : "Historical recorded traffic; monitoring is currently stopped."; }
function applyPosture(monitoring, stats, incidentCount) { const badge = document.getElementById("security-posture"); let label = "MONITORING UNAVAILABLE", detail = "Unable to load the current monitoring state.", level = "error"; if (monitoring) { if (!monitoring.running) { label = "MONITORING STOPPED"; detail = "The network is not currently being monitored by the sensor."; level = "stopped"; } else if (Number(stats?.new_or_unresolved_threats || 0) > 0 || incidentCount > 0) { label = "ATTENTION REQUIRED"; detail = "Persisted threats or open incidents require review."; level = "attention"; } else if (Number(stats?.detected_threats || 0) === 0) { label = "NO RECENT THREATS"; detail = "No persisted threat detections are currently available."; level = "normal"; } else { label = "MONITORING ACTIVE"; detail = "The sensor is active; review persisted historical detections as needed."; level = "active"; } } badge.textContent = label; badge.className = `posture-badge ${level}`; setText("posture-detail", detail); }

async function loadDashboardFromApi() {
  await window.aiNidsUserReady;
  const user = window.aiNidsCurrentUser;
  if (!user) return;
  const incidentVisible = user.role !== "user";
  document.getElementById("incident-kpi").hidden = !incidentVisible;
  document.getElementById("view-incidents").hidden = !incidentVisible;
  document.getElementById("view-live-sensor").hidden = !incidentVisible;
  const requests = [apiRequest("/api/capture/status"), apiRequest("/api/dashboard/stats"), apiRequest("/api/dashboard/network-activity"), apiRequest("/api/dashboard/threat-overview"), apiRequest("/api/dashboard/recent-threats"), incidentVisible ? apiRequest("/api/incidents") : Promise.resolve([])];
  const [monitoringResult, statsResult, activityResult, overviewResult, threatsResult, incidentsResult] = await Promise.allSettled(requests);
  const monitoring = monitoringResult.status === "fulfilled" ? monitoringResult.value : null;
  const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
  const incidents = incidentsResult.status === "fulfilled" ? incidentsResult.value : [];
  if (monitoring) applyMonitoringState(monitoring); else { setText("stat-monitoring", "UNAVAILABLE"); setText("stat-monitoring-detail", "Unable to load monitoring status"); }
  if (stats) { setText("stat-threats", stats.detected_threats); setText("stat-unresolved", `${stats.new_or_unresolved_threats} new or unresolved threats`); setText("stat-devices", stats.connected_devices); setText("stat-devices-detail", "Valid local endpoints active within the configured window"); } else { setText("stat-threats", "—"); setText("stat-unresolved", "Unable to load persisted detections"); setText("stat-devices", "—"); setText("stat-devices-detail", "Unable to load observed devices"); }
  let incidentCount = 0;
  if (incidentVisible) { if (incidentsResult.status === "fulfilled") { incidentCount = incidents.filter(item => !["Resolved", "Closed"].includes(item.status)).length; setText("stat-incidents", incidentCount); setText("stat-incidents-detail", "New, assigned, or investigating incident records"); } else { setText("stat-incidents", "—"); setText("stat-incidents-detail", "Unable to load incident records"); } }
  if (activityResult.status === "fulfilled") updateNetworkChart(activityResult.value); else { updateNetworkChart([]); setText("network-activity-empty", "Unable to load network activity."); document.getElementById("network-activity-empty").hidden = false; }
  if (overviewResult.status === "fulfilled") updateOverviewChart(overviewResult.value); else { updateOverviewChart([]); setText("threat-overview-empty", "Unable to load threat overview."); document.getElementById("threat-overview-empty").hidden = false; }
  if (threatsResult.status === "fulfilled") renderThreats(threatsResult.value); else renderThreats([], "Unable to load recent threat records.");
  applyPosture(monitoring, stats, incidentCount);
  if ([monitoringResult, statsResult, activityResult, overviewResult, threatsResult].some(result => result.status === "rejected")) dashboardMessage.textContent = "Some dashboard information could not be loaded. Check the affected section for details.";
}
if (threatTable) { initialiseCharts(); loadDashboardFromApi(); }
