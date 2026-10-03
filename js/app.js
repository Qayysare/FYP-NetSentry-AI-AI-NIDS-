// Shared same-origin API helper. API errors remain visible to users and developers.
async function apiRequest(endpoint, options = {}) {
  const isFormData = options.body instanceof FormData;
  const headers = { ...(options.headers || {}) };
  // The browser must set the multipart boundary when uploading a PCAP file.
  if (!isFormData && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(endpoint, { ...options, credentials: "include", headers });
  const responseText = await response.text();
  let payload;
  try { payload = responseText ? JSON.parse(responseText) : null; } catch (_error) { throw new Error("The server returned an invalid response. Check the Flask terminal."); }
  if (!payload) throw new Error("The server returned an empty response. Check the Flask terminal.");
  if (!response.ok || !payload.success) {
    const error = new Error(payload.message || "API request failed");
    error.status = response.status;
    throw error;
  }
  return payload.data;
}

(function () {
  const root = document.body.dataset.root || "";
  const page = location.pathname.split("/").pop() || "dashboard.html";
  const navigationGroups = [
    { label: "OVERVIEW", links: [["dashboard.html", "fa-table-columns", "Dashboard"]] },
    { label: "MONITORING", roles: ["admin", "analyst"], links: [["pages/live-sensor.html", "fa-tower-broadcast", "Live Sensor"], ["pages/manual-capture.html", "fa-sliders", "Manual AI Capture"], ["pages/ai-detection.html", "fa-brain", "AI Detection"], ["pages/examiner-demo.html", "fa-flask", "Examiner Demo"]] },
    { label: "SECURITY", links: [["pages/threat-alerts.html", "fa-triangle-exclamation", "Threat Alerts"], ["pages/incidents.html", "fa-ticket", "Incidents", ["admin", "analyst"]], ["pages/connected-devices.html", "fa-laptop", "Connected Devices"], ["pages/security-logs.html", "fa-clipboard-list", "Security Logs", ["admin", "analyst"]]] },
    { label: "ANALYSIS", links: [["pages/analytics.html", "fa-chart-pie", "Analytics", ["admin", "analyst"]], ["pages/reports.html", "fa-file-lines", "Reports"]] },
    { label: "ADMIN", roles: ["admin"], links: [["pages/user-management.html", "fa-users-gear", "User Management"], ["pages/settings.html", "fa-gear", "Settings"]] }
  ];
  const adminOnlyPages = new Set(["user-management.html", "settings.html", "password-reset-requests.html"]);
  const userVisiblePages = new Set(["dashboard.html", "threat-alerts.html", "connected-devices.html", "reports.html", "change-password.html"]);
  const href = path => root + path;
  const sidebar = document.getElementById("app-sidebar");
  const header = document.getElementById("app-header");

  function menuLink(link) { return `<a class="${link[0].endsWith(page) ? "active" : ""}" href="${href(link[0])}" title="${link[2]}"><i class="fa-solid ${link[1]}"></i><span>${link[2]}</span></a>`; }
  function roleCanSee(link, role) { return !link[3] || link[3].includes(role); }
  function renderNavigationGroups(role) {
    return navigationGroups
      .filter(group => !group.roles || group.roles.includes(role))
      .map(group => {
        const links = group.links.filter(link => roleCanSee(link, role));
        return links.length ? `<p class="nav-label">${group.label}</p><nav>${links.map(menuLink).join("")}</nav>` : "";
      }).join("");
  }
  function isPageAllowed(user) {
    if (user.role === "admin") return true;
    if (adminOnlyPages.has(page)) return false;
    if (user.role === "user") return userVisiblePages.has(page);
    return true;
  }
  function renderShell(user) {
    if (sidebar) {
      sidebar.innerHTML = `<aside class="sidebar"><div class="sidebar-top"><a class="brand" href="${href("dashboard.html")}" title="NetSentry AI"><i class="fa-solid fa-shield-halved"></i><span>NetSentry AI</span></a><button class="sidebar-collapse" id="sidebar-collapse" type="button" aria-label="Collapse sidebar" title="Collapse sidebar"><i class="fa-solid fa-angles-left"></i></button></div><div class="sidebar-navigation">${renderNavigationGroups(user.role)}</div><div class="sidebar-bottom"><nav><a href="${href("pages/change-password.html")}" title="Change Password"><i class="fa-solid fa-key"></i><span>Change Password</span></a><a class="logout-link" href="${href("index.html")}" id="logout-link" title="Logout"><i class="fa-solid fa-right-from-bracket"></i><span>Logout</span></a></nav></div></aside>`;
    }
    if (header) {
      const initial = (user.full_name || user.username || "U").trim().charAt(0).toUpperCase();
      const sessionLabel = user.role === "admin" ? "Administrator session" : user.role === "analyst" ? "SOC analyst session" : "Read-only user session";
      header.innerHTML = `<div class="topbar"><button class="icon-button menu-toggle" id="menu-toggle" aria-label="Open navigation"><i class="fa-solid fa-bars"></i></button><span class="system-status"><i class="fa-solid fa-circle"></i>${sessionLabel}</span><div class="topbar-actions"><button class="icon-button" id="notification-button" aria-label="Show notifications"><i class="fa-regular fa-bell"></i></button><div class="profile-chip"><span class="profile-avatar">${initial}</span><span>${user.full_name || user.username}</span></div></div></div>`;
    }
    document.getElementById("menu-toggle")?.addEventListener("click", () => sidebar.querySelector(".sidebar").classList.toggle("open"));
    const collapsed = localStorage.getItem("aiNidsSidebarCollapsed") === "true";
    function setSidebarCollapsed(value) {
      sidebar.querySelector(".sidebar").classList.toggle("collapsed", value);
      document.body.classList.toggle("sidebar-collapsed", value);
      const icon = document.querySelector("#sidebar-collapse i");
      if (icon) icon.className = `fa-solid ${value ? "fa-angles-right" : "fa-angles-left"}`;
      document.getElementById("sidebar-collapse")?.setAttribute("aria-label", value ? "Expand sidebar" : "Collapse sidebar");
      localStorage.setItem("aiNidsSidebarCollapsed", String(value));
    }
    setSidebarCollapsed(collapsed);
    document.getElementById("sidebar-collapse")?.addEventListener("click", () => setSidebarCollapsed(!sidebar.querySelector(".sidebar").classList.contains("collapsed")));
    document.getElementById("notification-button")?.addEventListener("click", () => alert("Demo notification: review your permitted NetSentry AI alerts."));
    document.getElementById("logout-link")?.addEventListener("click", async event => { event.preventDefault(); try { await apiRequest("/api/logout", { method: "POST" }); } finally { sessionStorage.removeItem("aiNidsUser"); location.href = href("index.html"); } });
  }

  async function loadAuthenticatedShell() {
    if (!sidebar && !header) return;
    try {
      const user = await apiRequest("/api/me");
      sessionStorage.setItem("aiNidsUser", JSON.stringify(user));
      if (user.must_change_password && page !== "change-password.html") {
        location.href = href(root ? "change-password.html" : "pages/change-password.html");
        return;
      }
      if (!isPageAllowed(user)) {
        location.href = href("dashboard.html");
        return;
      }
      renderShell(user);
      window.aiNidsCurrentUser = user;
    } catch (error) {
      console.warn("Session could not be loaded:", error.message);
      if (sidebar || header) location.href = href("index.html");
    }
  }
  window.aiNidsUserReady = loadAuthenticatedShell();

  const loginForm = document.getElementById("login-form");
  if (!loginForm) return;
  const password = document.getElementById("login-password");
  const message = document.getElementById("login-message");
  document.getElementById("password-toggle").onclick = () => { password.type = password.type === "password" ? "text" : "password"; };
  loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const identity = document.getElementById("login-email").value.trim();
    if (!identity || !password.value) { message.textContent = "Please enter an email/username and password to continue."; return; }
    try {
      const user = await apiRequest("/api/login", { method: "POST", body: JSON.stringify({ identity, password: password.value }) });
      sessionStorage.setItem("aiNidsUser", JSON.stringify(user));
      message.className = "form-message success";
      message.textContent = user.must_change_password ? "Password change required. Opening account pageâ€¦" : "Login successful. Opening dashboardâ€¦";
      setTimeout(() => { location.href = user.must_change_password ? "pages/change-password.html" : "dashboard.html"; }, 300);
    } catch (error) { message.textContent = error.message; }
  });
  document.getElementById("forgot-link").onclick = event => { event.preventDefault(); message.textContent = "Password reset requests are reviewed by an administrator."; };
})();
