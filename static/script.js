const tabs = Array.from(document.querySelectorAll(".tab"));
const panels = {
  text: document.getElementById("panel-text"),
  file: document.getElementById("panel-file"),
  repo: document.getElementById("panel-repo"),
};
const form = document.getElementById("scan-form");
const errorMessage = document.getElementById("error-message");
const results = document.getElementById("results");
const loading = document.getElementById("loading");
const scanButton = document.getElementById("scan-button");
let activeMode = "text";
let latestReport = null;

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    activeMode = tab.dataset.mode;
    tabs.forEach((item) => {
      const selected = item === tab;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-selected", String(selected));
    });
    Object.entries(panels).forEach(([mode, panel]) => {
      const visible = mode === activeMode;
      panel.hidden = !visible;
      panel.classList.toggle("hidden", !visible);
    });
    errorMessage.hidden = true;
  });
});

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
  results.hidden = true;
}

function addCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value;
  row.appendChild(cell);
  return cell;
}

function renderReport(report) {
  latestReport = report;
  const score = report.risk_score;
  document.getElementById("risk-value").textContent = String(score);
  document.getElementById("risk-caption").textContent =
    score === 0 ? "No issues found" : score >= 70 ? "High exposure risk" : score >= 35 ? "Review findings" : "Some exposure detected";
  const riskTrack = document.querySelector(".risk-track");
  riskTrack.setAttribute("aria-valuenow", String(score));
  document.getElementById("risk-bar").style.width = `${score}%`;
  document.getElementById("files-scanned").textContent =
    `${report.files_scanned} ${report.files_scanned === 1 ? "file" : "files"} scanned`;

  const countContainer = document.getElementById("severity-counts");
  countContainer.replaceChildren();
  ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach((severity) => {
    const item = document.createElement("div");
    item.className = "severity-count";
    const label = document.createElement("span");
    label.textContent = severity;
    const count = document.createElement("strong");
    count.textContent = String(report.summary[severity] || 0);
    item.append(label, count);
    countContainer.appendChild(item);
  });

  const body = document.getElementById("findings-body");
  body.replaceChildren();
  document.getElementById("finding-count").textContent =
    `${report.findings.length} ${report.findings.length === 1 ? "finding" : "findings"}`;
  document.getElementById("empty-state").hidden = report.findings.length !== 0;
  document.getElementById("table-wrap").hidden = report.findings.length === 0;
  report.findings.forEach((finding) => {
    const row = document.createElement("tr");
    addCell(row, `${finding.filename}:${finding.line_number}`);
    addCell(row, finding.secret_type);
    const severityCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${finding.severity.toLowerCase()}`;
    badge.textContent = finding.severity;
    severityCell.appendChild(badge);
    row.appendChild(severityCell);
    addCell(row, finding.masked_preview);
    addCell(row, finding.fix);
    body.appendChild(row);
  });
  errorMessage.hidden = true;
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  let url;
  let options;
  if (activeMode === "text") {
    const content = document.getElementById("content").value;
    if (!content.trim()) {
      showError("Paste some content to scan.");
      return;
    }
    url = "/api/scan/text";
    options = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        filename: document.getElementById("filename").value || "pasted.txt",
      }),
    };
  } else if (activeMode === "file") {
    const file = document.getElementById("file").files[0];
    if (!file) {
      showError("Choose a file to scan.");
      return;
    }
    if (file.size > 1_000_000) {
      showError("File exceeds the 1 MB upload limit.");
      return;
    }
    const data = new FormData();
    data.append("file", file);
    url = "/api/scan/file";
    options = { method: "POST", body: data };
  } else {
    url = "/api/scan/repo";
    options = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: document.getElementById("repo-url").value.trim() }),
    };
  }

  loading.hidden = false;
  scanButton.disabled = true;
  try {
    const response = await fetch(url, options);
    const payload = await response.json();
    if (!response.ok) {
      const detail = typeof payload.detail === "string" ? payload.detail : "The scan request could not be completed.";
      throw new Error(detail);
    }
    renderReport(payload);
  } catch (error) {
    showError(error instanceof Error ? error.message : "The scan request could not be completed.");
  } finally {
    loading.hidden = true;
    scanButton.disabled = false;
  }
});

document.getElementById("download-button").addEventListener("click", () => {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "leaklens-report.json";
  link.click();
  URL.revokeObjectURL(downloadUrl);
});
