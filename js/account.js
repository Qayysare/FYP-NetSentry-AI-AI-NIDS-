document.getElementById("change-password-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const current_password = document.getElementById("current-password").value;
  const new_password = document.getElementById("new-password").value;
  const confirm_password = document.getElementById("confirm-password").value;
  const message = document.getElementById("password-message");
  try {
    await apiRequest("/api/change-password", { method: "POST", body: JSON.stringify({ current_password, new_password, confirm_password }) });
    message.className = "form-message success";
    message.textContent = "Password changed. Opening dashboard…";
    setTimeout(() => { location.href = "../dashboard.html"; }, 400);
  } catch (error) {
    message.textContent = error.message;
  }
});
