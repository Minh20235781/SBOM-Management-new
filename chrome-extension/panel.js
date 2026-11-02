let isRecording = true;
let capturedRequests = [];
let syncCounter = 0;
let debounceTimer = null;

const BACKEND_STREAM_URL = "http://localhost:8080/api/reconciliation/live-f12-stream";

const reqCountEl = document.getElementById("reqCount");
const jsCountEl = document.getElementById("jsCount");
const syncCountEl = document.getElementById("syncCount");
const toggleBtn = document.getElementById("toggleBtn");
const syncNowBtn = document.getElementById("syncNowBtn");
const clearBtn = document.getElementById("clearBtn");
const statusBadge = document.getElementById("statusBadge");
const tableBody = document.getElementById("reqTableBody");

function updateStats() {
  reqCountEl.textContent = capturedRequests.length;
  jsCountEl.textContent = capturedRequests.filter(r => r.type === "script" || r.url.includes(".js")).length;
  syncCountEl.textContent = syncCounter;
}

function renderTable() {
  if (capturedRequests.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color: #9ca3af;">Chưa có yêu cầu mạng nào được ghi nhận. Tải lại trang web để bắt đầu.</td></tr>`;
    return;
  }

  const recent = capturedRequests.slice(-50).reverse();
  tableBody.innerHTML = recent.map(r => {
    const fName = r.url.split("/").pop()?.split("?")[0] || r.url;
    const sizeKb = (r.size / 1024).toFixed(1);
    return `
      <tr>
        <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.url}">
          ${fName}
        </td>
        <td style="color: #10b981; font-weight: 700;">${r.status}</td>
        <td style="color: #f472b6;">${r.type}</td>
        <td>${sizeKb} KB</td>
        <td style="color: #38bdf8;">${r.duration} ms</td>
      </tr>
    `;
  }).join("");
}

function sendToBackend() {
  if (capturedRequests.length === 0) return;

  chrome.devtools.inspectedWindow.eval("window.location.href", (href, isErr) => {
    const currentUrl = !isErr && href ? href : "active-tab";
    chrome.devtools.inspectedWindow.eval("document.title", (title) => {
      const pageTitle = title || "Inspected Tab";

      const payload = {
        url: currentUrl,
        title: pageTitle,
        collectorSource: "CHROME_DEVTOOLS_EXTENSION",
        entries: capturedRequests.map(r => ({
          name: r.url,
          initiatorType: r.type,
          size: r.size,
          duration: r.duration,
          startTime: r.startTime,
          status: r.status
        }))
      };

      fetch(BACKEND_STREAM_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
      .then(res => res.json())
      .then(() => {
        syncCounter++;
        updateStats();
      })
      .catch(err => {
        console.warn("Chưa thể gửi sang backend:", err.message);
      });
    });
  });
}

// Bắt sự kiện mạng qua DevTools Network API
chrome.devtools.network.onRequestFinished.addListener((request) => {
  if (!isRecording) return;

  const url = request.request?.url || "";
  if (!url || url.includes("8080") || url.includes("live-f12-stream")) {
    return;
  }

  let resType = "other";
  const mime = request.response?.content?.mimeType || "";
  if (url.includes(".js") || mime.includes("javascript")) resType = "script";
  else if (url.includes(".css") || mime.includes("css")) resType = "stylesheet";
  else if (mime.includes("json") || request._resourceType === "xhr" || request._resourceType === "fetch") resType = "fetch";
  else if (url.includes(".html") || mime.includes("html")) resType = "document";

  const size = request.response?.bodySize > 0 
    ? request.response.bodySize 
    : (request.response?._transferSize || 12000);

  const duration = Math.round(request.time || 20);

  capturedRequests.push({
    url: url,
    status: request.response?.status || 200,
    type: resType,
    size: size,
    duration: duration,
    startTime: Math.round(request.startedDateTime ? new Date(request.startedDateTime).getTime() : Date.now())
  });

  updateStats();
  renderTable();

  // Tự động đẩy sang Backend mỗi khi có thêm tài nguyên mới
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(sendToBackend, 1000);
});

toggleBtn.addEventListener("click", () => {
  isRecording = !isRecording;
  if (isRecording) {
    statusBadge.textContent = "Đang ghi nhận thời gian thực";
    statusBadge.className = "badge badge-live";
    toggleBtn.textContent = "Tạm dừng ghi";
    toggleBtn.className = "btn-primary";
  } else {
    statusBadge.textContent = "Đã tạm dừng";
    statusBadge.className = "badge badge-off";
    toggleBtn.textContent = "Tiếp tục ghi";
    toggleBtn.className = "btn-secondary";
  }
});

syncNowBtn.addEventListener("click", () => {
  sendToBackend();
});

clearBtn.addEventListener("click", () => {
  capturedRequests = [];
  syncCounter = 0;
  updateStats();
  renderTable();
});

