const analyticsMessage = document.getElementById("analytics-message");
const chartPalette = ["#42a5f5", "#37c88b", "#f4ad42", "#f06170", "#9b8cff"];
const sharedOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#cbd5e1" } }, tooltip: { backgroundColor: "#0d1727" } }, scales: { x: { grid: { color: "#26354b" }, ticks: { color: "#9cacbf" } }, y: { beginAtZero: true, grid: { color: "#26354b" }, ticks: { color: "#9cacbf" } } } };
let trendChart;
let attackChart;
let severityChart;
let statusChart;

function doughnutOptions() { return { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1" } } } }; }
function emptyRows(rows) { return rows.length ? rows : [{ label: "No threat data", value: 0 }]; }
function setChartData(chart, rows) { const safeRows = emptyRows(rows); chart.data.labels = safeRows.map(item => item.label); chart.data.datasets[0].data = safeRows.map(item => item.value); chart.update(); }

function initialiseCharts() {
  trendChart = new Chart(document.getElementById("trend-chart"), { type: "line", data: { labels: ["No threat data"], datasets: [{ label: "Detections", data: [0], borderColor: "#f06170", tension: 0.35, fill: true, backgroundColor: "#f0617026" }] }, options: sharedOptions });
  attackChart = new Chart(document.getElementById("attack-chart"), { type: "bar", data: { labels: ["No threat data"], datasets: [{ label: "Threats", data: [0], backgroundColor: "#42a5f5" }] }, options: sharedOptions });
  severityChart = new Chart(document.getElementById("severity-chart"), { type: "doughnut", data: { labels: ["No threat data"], datasets: [{ data: [0], backgroundColor: chartPalette, borderWidth: 0 }] }, options: doughnutOptions() });
  statusChart = new Chart(document.getElementById("status-chart"), { type: "doughnut", data: { labels: ["No threat data"], datasets: [{ data: [0], backgroundColor: chartPalette, borderWidth: 0 }] }, options: doughnutOptions() });
}

async function loadAnalytics() {
  try {
    const [trend, attackTypes, severities, statuses] = await Promise.all([
      apiRequest("/api/analytics/threat-trend"), apiRequest("/api/analytics/threat-distribution"),
      apiRequest("/api/analytics/severity-distribution"), apiRequest("/api/analytics/status-distribution"),
    ]);
    setChartData(trendChart, trend);
    setChartData(attackChart, attackTypes);
    setChartData(severityChart, severities);
    setChartData(statusChart, statuses);
  } catch (error) { analyticsMessage.textContent = error.message || "Analytics data could not be loaded."; }
}

initialiseCharts();
loadAnalytics();
