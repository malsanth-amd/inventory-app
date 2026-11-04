// FlashTools Web - job dispatch + live log/status streaming.
// This is the web equivalent of flash_gui.py's QProcess wiring: instead of
// Qt signals driving widgets directly, we open an EventSource (SSE) onto
// /api/jobs/{id}/stream and update the DOM as lines arrive.

let targetsFile = null;
let activeJobId = null;
let activeEventSource = null;

const el = (id) => document.getElementById(id);

el("targets-csv").addEventListener("change", (e) => {
  targetsFile = e.target.files[0] || null;
  const preview = el("targets-preview");
  if (!targetsFile) {
    preview.textContent = "";
    return;
  }
  targetsFile.text().then((text) => {
    const lines = text.trim().split("\n");
    preview.textContent = `${Math.max(lines.length - 1, 0)} target system(s) loaded from ${targetsFile.name}`;
  });
});

el("confirm-flash").addEventListener("change", (e) => {
  el("flash-now-btn").disabled = !e.target.checked || !targetsFile;
});

el("refresh-btn").addEventListener("click", async () => {
  el("refresh-btn").disabled = true;
  appendLog("=== Starting firmware refresh from the BKC page ===");
  try {
    const resp = await fetch("/api/jobs/refresh", { method: "POST" });
    const data = await resp.json();
    if (data.error) {
      appendLog(`ERROR: ${data.error}`);
      el("refresh-btn").disabled = false;
      return;
    }
    appendLog(`$ ${data.cmd_display}`);
    streamJob(data.job_id, () => { el("refresh-btn").disabled = false; });
  } catch (e) {
    appendLog(`ERROR: ${e}`);
    el("refresh-btn").disabled = false;
  }
});

el("dry-run-btn").addEventListener("click", () => startFlashJob(true));
el("flash-now-btn").addEventListener("click", () => startFlashJob(false));

el("stop-btn").addEventListener("click", async () => {
  if (!activeJobId) return;
  await fetch(`/api/jobs/${activeJobId}/stop`, { method: "POST" });
  appendLog("=== Stop requested ===");
});

async function startFlashJob(dryRun) {
  if (!targetsFile) {
    appendLog("ERROR: upload a targets CSV first.");
    return;
  }
  setRunButtonsEnabled(false);
  clearLog();
  clearStatusTable();
  appendLog(dryRun ? "=== Starting dry run ===" : "=== Starting FLASH NOW ===");

  const form = new FormData();
  form.append("targets_csv", targetsFile);
  form.append("dry_run", dryRun ? "true" : "false");
  if (el("bmc-user").value) form.append("bmc_user", el("bmc-user").value);
  if (el("bmc-pass").value) form.append("bmc_pass", el("bmc-pass").value);

  // Manual firmware override: any file the user picked under "1b." gets
  // sent as fw_<board>_<component>, matched server-side to only the rows
  // whose platform equals <board>.
  document.querySelectorAll(".fw-file").forEach((input) => {
    if (input.files.length > 0) {
      form.append(`fw_${input.dataset.board}_${input.dataset.component}`, input.files[0]);
    }
  });
  document.querySelectorAll(".fw-version").forEach((input) => {
    if (input.value.trim()) {
      form.append(`fw_${input.dataset.board}_${input.dataset.component}_version`, input.value.trim());
    }
  });

  try {
    const resp = await fetch(`/api/jobs/flash?dry_run=${dryRun}`, { method: "POST", body: form });
    const data = await resp.json();
    if (data.error) {
      appendLog(`ERROR: ${data.error}`);
      setRunButtonsEnabled(true);
      return;
    }
    appendLog(`$ ${data.cmd_display}`);
    el("stop-btn").disabled = false;
    streamJob(data.job_id, () => setRunButtonsEnabled(true));
  } catch (e) {
    appendLog(`ERROR: ${e}`);
    setRunButtonsEnabled(true);
  }
}

function streamJob(jobId, onDone) {
  activeJobId = jobId;
  if (activeEventSource) activeEventSource.close();
  const source = new EventSource(`/api/jobs/${jobId}/stream`);
  activeEventSource = source;

  source.onmessage = (ev) => {
    const data = JSON.parse(ev.data);
    if (data.line !== undefined) appendLog(data.line);
    if (data.statuses) renderStatuses(data.statuses);
  };
  source.addEventListener("done", (ev) => {
    const data = JSON.parse(ev.data);
    appendLog(`=== Job finished (exit code ${data.exit_code}) ===`);
    if (data.statuses) renderStatuses(data.statuses);
    source.close();
    activeEventSource = null;
    activeJobId = null;
    el("stop-btn").disabled = true;
    onDone();
  });
  source.onerror = () => {
    appendLog("ERROR: lost connection to the job stream.");
    source.close();
  };
}

function setRunButtonsEnabled(enabled) {
  el("dry-run-btn").disabled = !enabled;
  el("flash-now-btn").disabled = !enabled || !el("confirm-flash").checked || !targetsFile;
}

function appendLog(line) {
  const log = el("output-log");
  log.textContent += line + "\n";
  log.scrollTop = log.scrollHeight;
}

function clearLog() {
  el("output-log").textContent = "";
}

function clearStatusTable() {
  el("status-rows").innerHTML = "";
}

function renderStatuses(statuses) {
  const tbody = el("status-rows");
  tbody.innerHTML = "";
  for (const [name, info] of Object.entries(statuses)) {
    const tr = document.createElement("tr");
    const statusClass = info.status === "ok" ? "status-ok" : "status-failed";
    tr.innerHTML = `
      <td>${name}</td>
      <td class="${statusClass}">${info.detail}</td>
      <td>${info.elapsed}s</td>
      <td>${info.log}</td>
    `;
    tbody.appendChild(tr);
  }
}
