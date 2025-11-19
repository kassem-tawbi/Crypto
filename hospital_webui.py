# hospital_webui.py
# FastAPI web console for a HospitalNode (no manual IP/port entry).

import argparse
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import uvicorn

from hospital_node import HospitalNode, CONFIG
from registry import list_hospitals


class RequestFileBody(BaseModel):
    target: str
    file_name: str


class ApproveBody(BaseModel):
    id: str
    approved: bool


def create_app(hospital_name: str, public_host: str | None = None) -> FastAPI:
    if hospital_name not in CONFIG:
        raise ValueError(f"Unknown hospital '{hospital_name}'")

    node = HospitalNode(hospital_name, public_host=public_host)
    node.start_server()
    logger = node.logger

    app = FastAPI(title=f"{hospital_name} Secure P2P Node")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        # Target hospital dropdown options from MongoDB registry (exclude myself)
        try:
            peers = list_hospitals(exclude_name=hospital_name)
        except Exception as e:
            logger.error(f"Failed to load peers from registry: {e}")
            peers = []

        options_html = "".join(
            f'<option value="{doc["name"]}">{doc["name"]}</option>'
            for doc in peers
            if doc.get("name")
        ) or '<option value="">(no peers registered)</option>'

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>{hospital_name} - Secure P2P Console</title>
  <style>
    :root {{
      --bg-page: #f5f5f7;
      --bg-card: #ffffff;
      --bg-subtle: #f9fafb;
      --border-subtle: #e5e7eb;
      --shadow-soft: 0 8px 24px rgba(15,23,42,0.08);
      --text-main: #111827;
      --text-muted: #6b7280;
      --accent: #059669;
      --accent-soft: #ecfdf5;
      --accent-blue: #2563eb;
      --danger: #dc2626;
      --danger-soft: #fef2f2;
      --radius-lg: 14px;
      --radius-md: 10px;
      --font: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      padding: 0;
      font-family: var(--font);
      background-color: var(--bg-page);
      color: var(--text-main);
    }}
    header {{
      padding: 16px 24px 12px;
      background-color: #ffffff;
      border-bottom: 1px solid var(--border-subtle);
      box-shadow: 0 4px 8px rgba(15,23,42,0.04);
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    header h1 {{
      margin: 0;
      font-size: 20px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    header h1 span.logo-mark {{
      width: 18px;
      height: 18px;
      border-radius: 6px;
      background: radial-gradient(circle at 20% 0, #22c55e, #14b8a6);
      box-shadow: 0 0 10px rgba(34,197,94,0.7);
    }}
    header .meta {{
      margin-top: 6px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      font-size: 11px;
    }}
    header .pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 2px 9px;
      border-radius: 999px;
      background-color: var(--bg-subtle);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
    }}
    header .pill span.dot {{
      width: 6px;
      height: 6px;
      border-radius: 999px;
      background: radial-gradient(circle, #22c55e 0, #16a34a 70%);
    }}

    main {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 18px 24px 24px;
    }}
    .section {{
      margin-bottom: 18px;
    }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    .section-title {{
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #4b5563;
    }}
    .section-subtitle {{
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }}
    .cards-grid {{
      display: grid;
      grid-template-columns: minmax(260px, 1.1fr) minmax(260px, 1.1fr);
      gap: 14px;
    }}
    .card {{
      background-color: var(--bg-card);
      border-radius: var(--radius-lg);
      padding: 12px 14px 11px;
      box-shadow: var(--shadow-soft);
      border: 1px solid var(--border-subtle);
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 4px;
    }}
    .card-header-left h2 {{
      margin: 0;
      font-size: 15px;
      font-weight: 600;
    }}
    .pill-label {{
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      font-size: 9px;
      border-radius: 999px;
      background-color: var(--accent-soft);
      color: #047857;
      border: 1px solid #bbf7d0;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .pill-label.blue {{
      background-color: #eff6ff;
      color: #1d4ed8;
      border-color: #bfdbfe;
    }}

    label {{
      font-size: 11px;
      color: #4b5563;
      display: block;
      margin-bottom: 2px;
    }}
    input, select {{
      font-size: 12px;
      padding: 6px 8px;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
      width: 100%;
      outline: none;
      transition: all 0.15s ease;
      background-color: #f9fafb;
    }}
    input::placeholder {{
      color: #9ca3af;
    }}
    input:focus, select:focus {{
      border-color: var(--accent-blue);
      box-shadow: 0 0 0 1px rgba(37,99,235,0.15);
      background-color: #ffffff;
    }}
    select {{
      cursor: pointer;
    }}
    .row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .col {{
      flex: 1;
      min-width: 150px;
    }}

    .btn {{
      font-size: 12px;
      padding: 6px 13px;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: linear-gradient(90deg, #10b981, #059669);
      color: white;
      box-shadow: 0 2px 6px rgba(16,185,129,0.5);
      transition: all 0.15s ease;
      font-weight: 500;
    }}
    .btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 4px 10px rgba(16,185,129,0.6);
    }}
    .btn:disabled {{
      opacity: 0.6;
      cursor: default;
      box-shadow: none;
      transform: none;
    }}
    .btn-secondary {{
      background: linear-gradient(90deg, #6b7280, #4b5563);
      box-shadow: 0 2px 6px rgba(55,65,81,0.4);
    }}
    .btn-secondary:hover {{
      box-shadow: 0 4px 9px rgba(55,65,81,0.5);
    }}
    .btn-approve {{
      background: linear-gradient(90deg, #22c55e, #16a34a);
      box-shadow: 0 2px 6px rgba(22,163,74,0.5);
    }}
    .btn-deny {{
      background: linear-gradient(90deg, #ef4444, #b91c1c);
      box-shadow: 0 2px 6px rgba(239,68,68,0.5);
    }}
    .btn-deny:hover {{
      box-shadow: 0 4px 10px rgba(239,68,68,0.6);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 4px;
      font-size: 11px;
    }}
    th, td {{
      padding: 6px 7px;
      border-bottom: 1px solid var(--border-subtle);
      text-align: left;
      vertical-align: middle;
    }}
    th {{
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #9ca3af;
      background-color: var(--bg-subtle);
    }}
    tr:hover td {{
      background-color: #f3f4ff;
    }}
    tr.selected td {{
      background-color: #dbeafe !important;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 1px 6px;
      border-radius: 999px;
      font-size: 9px;
      gap: 4px;
    }}
    .badge-local {{
      background-color: #ecfdf5;
      color: #166534;
      border: 1px solid #bbf7d0;
    }}
    .badge-received {{
      background-color: #eff6ff;
      color: #1d4ed8;
      border: 1px solid #bfdbfe;
    }}
    .file-download-btn {{
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      background-color: #111827;
      color: #f9fafb;
      box-shadow: 0 1px 4px rgba(15,23,42,0.5);
      transition: all 0.15s ease;
    }}
    .file-download-btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 3px 8px rgba(15,23,42,0.6);
    }}

    #status {{
      font-size: 10px;
      color: var(--text-muted);
      margin-left: 4px;
    }}
    .status-error {{
      color: var(--danger) !important;
    }}

    .badge-level {{
      font-weight: 500;
      border-radius: 999px;
      padding: 1px 7px;
      font-size: 9px;
    }}
    .badge-level-INFO {{
      background-color: #eff6ff;
      color: #1d4ed8;
      border: 1px solid #bfdbfe;
    }}
    .badge-level-WARNING {{
      background-color: #fef9c3;
      color: #92400e;
      border: 1px solid #facc15;
    }}
    .badge-level-ERROR,
    .badge-level-CRITICAL {{
      background-color: #fee2e2;
      color: #b91c1c;
      border: 1px solid #fecaca;
    }}
    .badge-level-DEBUG {{
      background-color: #e5e7eb;
      color: #374151;
      border: 1px solid #cbd5e1;
    }}

    @media (max-width: 860px) {{
      main {{
        padding: 14px 16px 18px;
      }}
      .cards-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>
      <span class="logo-mark"></span>
      {hospital_name} – Secure Record Exchange
    </h1>
    <div class="meta">
      <span class="pill"><span class="dot"></span> Node online</span>
      <span class="pill">Hospital: {hospital_name}</span>
    </div>
  </header>

  <main>
    <!-- SECTION 1: Outgoing & Incoming (top row) -->
    <section class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Session control</div>
        </div>
      </div>
      <div class="cards-grid">
        <!-- Outgoing (Client) -->
        <div class="card">
          <div class="card-header">
            <div class="card-header-left">
              <h2>Outgoing file request</h2>
            </div>
            <span class="pill-label">Client</span>
          </div>

          <div class="row">
            <div class="col">
              <label for="target">Target hospital</label>
              <select id="target">
                {options_html}
              </select>
            </div>
          </div>

          <div>
            <label for="file">File name</label>
            <input id="file" placeholder="patient_123.txt" />
          </div>

          <div style="margin-top:8px; display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
            <button class="btn" onclick="sendRequest()">
              <span class="icon">⇢</span>
              <span>Send request</span>
            </button>
            <span id="status"></span>
          </div>
        </div>

        <!-- Incoming (Server approvals) -->
        <div class="card">
          <div class="card-header">
            <div class="card-header-left">
              <h2>Incoming requests</h2>
            </div>
            <span class="pill-label blue">Server</span>
          </div>

          <table id="pending-table">
            <thead>
              <tr>
                <th>Request ID</th>
                <th>From</th>
                <th>File</th>
              </tr>
            </thead>
            <tbody id="pending-body">
              <tr><td colspan="3" style="color:#9ca3af;">No pending requests.</td></tr>
            </tbody>
          </table>

          <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">
            <button class="btn btn-approve" onclick="approveSelected(true)">
              <span class="icon">✔</span>
              <span>Approve selected</span>
            </button>
            <button class="btn btn-deny" onclick="approveSelected(false)">
              <span class="icon">✖</span>
              <span>Deny selected</span>
            </button>
            <button class="btn btn-secondary" onclick="loadPending()">
              <span class="icon">↻</span>
              <span>Refresh</span>
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- SECTION 2: File repository & Logs (bottom row) -->
    <section class="section">
      <div class="cards-grid">
        <!-- File repo -->
        <div class="card">
          <div class="card-header">
            <div class="card-header-left">
              <h2>File repository</h2>
            </div>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <span></span>
            <button class="file-download-btn" onclick="reloadFiles()">Refresh list</button>
          </div>
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Location</th>
                <th>Size</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="files-body">
              <tr><td colspan="4" style="color:#9ca3af;">No files detected yet.</td></tr>
            </tbody>
          </table>
        </div>

        <!-- Logs -->
        <div class="card">
          <div class="card-header">
            <div class="card-header-left">
              <h2>Activity & logs</h2>
            </div>
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <span class="section-subtitle">Newest events shown first.</span>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <button class="btn btn-secondary" onclick="loadLogs()">
                <span class="icon">📜</span>
                <span>Refresh events</span>
              </button>
              <button class="file-download-btn" onclick="downloadLogs()">
                Download full log file
              </button>
            </div>
          </div>

          <table>
            <thead>
              <tr>
                <th style="width:150px;">Timestamp</th>
                <th style="width:80px;">Level</th>
                <th>Event</th>
              </tr>
            </thead>
            <tbody id="logs-body">
              <tr><td colspan="3" style="color:#9ca3af;">No log entries yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </main>

  <script>
    let selectedId = null;

    function setStatus(msg, isError) {{
      const el = document.getElementById('status');
      el.textContent = msg || '';
      if (!msg) {{
        el.classList.remove('status-error');
        return;
      }}
      if (isError) {{
        el.classList.add('status-error');
      }} else {{
        el.classList.remove('status-error');
      }}
    }}

    function selectRow(id) {{
      selectedId = id;
      const rows = document.querySelectorAll('#pending-body tr');
      rows.forEach(r => r.classList.remove('selected'));
      const row = document.getElementById('row-' + id);
      if (row) row.classList.add('selected');
    }}

    async function loadPending() {{
      try {{
        const res = await fetch('/api/pending');
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('pending-body');
        tbody.innerHTML = '';

        if (!data.length) {{
          tbody.innerHTML = '<tr><td colspan="3" style="color:#9ca3af;">No pending requests.</td></tr>';
          selectedId = null;
          return;
        }}

        for (const req of data) {{
          const tr = document.createElement('tr');
          tr.id = 'row-' + req.id;
          tr.onclick = () => selectRow(req.id);

          const tdId = document.createElement('td');
          tdId.textContent = req.id;
          const tdFrom = document.createElement('td');
          tdFrom.textContent = req.requester;
          const tdFile = document.createElement('td');
          tdFile.textContent = req.file;

          tr.appendChild(tdId);
          tr.appendChild(tdFrom);
          tr.appendChild(tdFile);
          tbody.appendChild(tr);
        }}

        if (selectedId) {{
          const row = document.getElementById('row-' + selectedId);
          if (row) row.classList.add('selected');
        }}
      }} catch (e) {{}}
    }}

    async function sendRequest() {{
      const target = document.getElementById('target').value.trim();
      const file = document.getElementById('file').value.trim();

      if (!target) {{
        alert('Select a target hospital.');
        return;
      }}
      if (!file) {{
        alert('File name is required.');
        return;
      }}

      setStatus('Sending request...');
      try {{
        const res = await fetch('/api/request', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ target, file_name: file }})
        }});
        const txt = await res.text();
        let js = null;
        try {{ js = JSON.parse(txt); }} catch (e) {{}}

        if (!res.ok) {{
          setStatus((js && js.detail) ? js.detail : ('Request failed: ' + txt), true);
        }} else {{
          setStatus((js && js.detail) || 'Request sent successfully.');
          reloadFiles();
          loadLogs();
        }}
      }} catch (e) {{
        setStatus('Error sending request.', true);
      }}
    }}

    async function approveSelected(approved) {{
      if (!selectedId) {{
        alert('Select a request row first.');
        return;
      }}
      try {{
        const res = await fetch('/api/approve', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ id: selectedId, approved }})
        }});
        const txt = await res.text();
        let js = null;
        try {{ js = JSON.parse(txt); }} catch (e) {{}}

        if (!res.ok) {{
          setStatus((js && js.detail) ? js.detail : ('Approve/deny failed: ' + txt), true);
        }} else {{
          setStatus((js && js.detail) || 'Decision recorded.');
          selectedId = null;
          await loadPending();
          loadLogs();
        }}
      }} catch (e) {{
        setStatus('Error sending decision.', true);
      }}
    }}

    async function reloadFiles() {{
      try {{
        const res = await fetch('/api/files');
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('files-body');
        tbody.innerHTML = '';

        if (!data.length) {{
          tbody.innerHTML = '<tr><td colspan="4" style="color:#9ca3af;">No files detected yet.</td></tr>';
          return;
        }}

        for (const f of data) {{
          const tr = document.createElement('tr');

          const tdName = document.createElement('td');
          tdName.textContent = f.name;

          const tdLoc = document.createElement('td');
          const badge = document.createElement('span');
          badge.classList.add('badge');
          if (f.kind === 'data') {{
            badge.classList.add('badge-local');
            badge.textContent = 'Local';
          }} else {{
            badge.classList.add('badge-received');
            badge.textContent = 'Received';
          }}
          tdLoc.appendChild(badge);

          const tdSize = document.createElement('td');
          tdSize.textContent = f.size_human;

          const tdAct = document.createElement('td');
          const btn = document.createElement('button');
          btn.className = 'file-download-btn';
          btn.textContent = 'Download';
          btn.onclick = () => {{
            window.location = `/files/${{f.kind}}/${{encodeURIComponent(f.name)}}`;
          }};
          tdAct.appendChild(btn);

          tr.appendChild(tdName);
          tr.appendChild(tdLoc);
          tr.appendChild(tdSize);
          tr.appendChild(tdAct);

          tbody.appendChild(tr);
        }}
      }} catch (e) {{}}
    }}

    async function loadLogs() {{
      try {{
        const res = await fetch('/api/logs');
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';

        if (!data.length) {{
          tbody.innerHTML = '<tr><td colspan="3" style="color:#9ca3af;">No log entries yet.</td></tr>';
          return;
        }}

        data.forEach((entry) => {{
          const tr = document.createElement('tr');

          const tdTs = document.createElement('td');
          tdTs.textContent = entry.ts || '';

          const tdLevel = document.createElement('td');
          const lvl = (entry.level || 'INFO').toUpperCase();
          const lvlBadge = document.createElement('span');
          lvlBadge.textContent = lvl;
          lvlBadge.classList.add('badge-level');
          if (lvl === 'INFO') lvlBadge.classList.add('badge-level-INFO');
          else if (lvl === 'WARNING') lvlBadge.classList.add('badge-level-WARNING');
          else if (lvl === 'ERROR' || lvl === 'CRITICAL') lvlBadge.classList.add('badge-level-ERROR');
          else if (lvl === 'DEBUG') lvlBadge.classList.add('badge-level-DEBUG');
          tdLevel.appendChild(lvlBadge);

          const tdMsg = document.createElement('td');
          tdMsg.textContent = entry.summary || '';

          tr.appendChild(tdTs);
          tr.appendChild(tdLevel);
          tr.appendChild(tdMsg);
          tbody.appendChild(tr);
        }});
      }} catch (e) {{}}
    }}

    function downloadLogs() {{
      window.location = '/logs/download';
    }}

    // Bootstrap
    setInterval(loadPending, 800);
    loadPending();
    reloadFiles();
    loadLogs();
  </script>
</body>
</html>
        """

    # ===== API: approvals =====

    @app.get("/api/pending")
    async def api_pending():
        return node.get_pending_approvals()

    @app.post("/api/approve")
    async def api_approve(body: ApproveBody):
        node.resolve_approval(body.id, body.approved)
        return {"detail": f"Decision recorded for {body.id}."}

    # ===== API: send request =====

    @app.post("/api/request")
    async def api_request(body: RequestFileBody):
        # We rely on MongoDB registry + HospitalNode.request_record
        ok = node.request_record(body.target, body.file_name)
        if not ok:
            raise HTTPException(
                status_code=500,
                detail="Request failed. Check node logs for detailed reason.",
            )
        return {"detail": "Request succeeded. See logs for crypto details."}

    # ===== API: file repository =====

    @app.get("/api/files")
    async def api_files():
        files = []

        def add_files_from(dir_path: str, kind: str):
            if not os.path.isdir(dir_path):
                return
            for name in os.listdir(dir_path):
                full = os.path.join(dir_path, name)
                if not os.path.isfile(full):
                    continue
                size = os.path.getsize(full)
                files.append(
                    {
                        "name": name,
                        "kind": kind,
                        "size": size,
                        "size_human": _human_size(size),
                    }
                )

        add_files_from(node.conf["data_dir"], "data")
        add_files_from(node.conf["received_dir"], "received")
        files.sort(key=lambda f: (f["kind"] != "received", f["name"].lower()))
        return files

    @app.get("/files/{kind}/{filename}")
    async def download_file(kind: str, filename: str):
        if kind not in ("data", "received"):
            raise HTTPException(status_code=400, detail="Invalid file kind.")
        if "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename.")

        dir_path = (
            node.conf["data_dir"] if kind == "data" else node.conf["received_dir"]
        )
        full_path = os.path.join(dir_path, filename)
        if not os.path.isfile(full_path):
            raise HTTPException(status_code=404, detail="File not found.")

        return FileResponse(
            full_path, filename=filename, media_type="application/octet-stream"
        )

    # ===== API: logs (normalized, newest-first) =====

    @app.get("/api/logs")
    async def api_logs(limit: int = 200):
        """
        Return last N log lines as:
          - ts: timestamp
          - level: log level
          - summary: high-level event description

        Ordered with newest entries first.
        """
        log_path = os.path.join("logs", f"{hospital_name}.log")
        if not os.path.exists(log_path):
            return []

        lines = _tail(log_path, limit)
        entries = []
        for line in lines:
            line = line.rstrip("\n")
            ts = ""
            level = ""
            msg = line
            try:
                # Format: "YYYY-MM-DD HH:MM:SS [LEVEL] [Hospital_X] message..."
                parts = line.split("]", 2)
                if len(parts) >= 3:
                    ts = parts[0][:19]
                    first = parts[0]
                    lb = first.find("[")
                    if lb != -1:
                        level = first[lb + 1 :].strip()
                    msg = parts[2].strip()
            except Exception:
                pass

            summary = _normalize_log_message(msg)
            entries.append(
                {
                    "ts": ts or None,
                    "level": level or "INFO",
                    "summary": summary,
                }
            )

        # newest first
        entries.reverse()
        return entries

    # ===== LOG FILE DOWNLOAD =====

    @app.get("/logs/download")
    async def download_logs():
        """
        Download the raw log file for this hospital node.
        """
        log_path = os.path.join("logs", f"{hospital_name}.log")
        if not os.path.exists(log_path):
            raise HTTPException(status_code=404, detail="Log file not found.")
        return FileResponse(
            path=log_path,
            filename=f"{hospital_name}.log",
            media_type="text/plain",
        )

    app.state.node = node
    app.state.logger = logger
    return app


# ===== Helpers =====


def _human_size(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024.0:
            return f"{num:.0f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def _tail(path: str, n: int):
    """Return last n lines from file path, efficiently."""
    if n <= 0:
        return []
    size = os.path.getsize(path)
    if size == 0:
        return []
    chunk = 1024
    data = b""
    with open(path, "rb") as f:
        while size > 0 and data.count(b"\n") <= n:
            read_size = min(chunk, size)
            size -= read_size
            f.seek(size)
            data = f.read(read_size) + data
    lines = data.splitlines()[-n:]
    return [ln.decode("utf-8", errors="replace") for ln in lines]


def _parse_fields_from_message(msg: str) -> dict:
    """
    Parse "Op | key=value | key2=value2" style messages into a dict of key/value.
    """
    parts = msg.split(" | ")
    fields = {}
    for seg in parts[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def _normalize_log_message(msg: str) -> str:
    """
    Turn detailed crypto log lines into short, high-level activity summaries.
    Always prefer a concise description over raw details.
    """
    # Structured logs with "Op | key=value | ..." format
    if " | " in msg:
        op = msg.split(" | ", 1)[0].strip()
        fields = _parse_fields_from_message(msg)

        if op == "Request_Received":
            src = fields.get("from_hospital") or fields.get("from")
            mprev = fields.get("message_preview", "")
            filename = None
            if "Request:" in mprev:
                filename = mprev.split("Request:", 1)[-1]
            parts = ["Incoming file request"]
            if src:
                parts.append(f"from {src}")
            if filename:
                parts.append(f"for '{filename}'")
            return " ".join(parts)

        if op == "VerifySignature_Success":
            return "Requester signature verified."

        if op == "VerifySignature_Failed":
            return "Signature verification failed."

        if op == "SessionKeys_Generated":
            return "Session keys generated for this transfer."

        if op == "RSA_EncryptKeys_Done":
            return "Session keys encrypted with recipient's RSA key."

        if op in ("RSA_DecryptKeys_Start", "RSA_DecryptKeys_Done"):
            return "Session keys decrypted with local RSA key."

        if op == "AES_Encrypt_Done":
            return "Record encrypted with AES-256."

        if op == "AES_Decrypt_Done":
            return "Record decrypted with AES-256."

        if op == "HMAC_Generate_Done":
            return "HMAC-SHA256 tag generated."

        if op == "HMAC_Verify_Success":
            return "HMAC check succeeded (data intact)."

        if op == "HMAC_Verify_Failed":
            return "HMAC check failed (data may be corrupted)."

        if op == "File_Read":
            fname = fields.get("file")
            if fname:
                return f"File '{fname}' prepared for transfer."
            return "File prepared for transfer."

        # Default: generic op description
        short = op.replace("_", " ")
        if len(short) > 120:
            short = short[:117] + "..."
        return short

    # Non-structured logs: map common phrases to high-level descriptions
    text = msg
    lowered = text.lower()

    if "starting node" in lowered:
        return "Node started."

    if "server listening on" in lowered:
        return "Server is listening for incoming connections."

    if "accepted connection from" in lowered:
        return "Incoming connection accepted."

    if "request approved" in lowered:
        return "Request approved by staff."

    if "request denied" in lowered:
        return "Request denied by staff."

    if "secure package for" in lowered and "sent to" in lowered:
        return "Encrypted package sent to requesting hospital."

    if "saved record to" in lowered:
        return "Decrypted record saved to storage."

    if "connection from" in lowered and "closed" in lowered:
        return "Connection closed."

    # Fallback: very generic summary, no details
    return "System event."


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hospital", choices=list(CONFIG.keys()))
    parser.add_argument("--host", default="127.0.0.1", help="Host for the web UI (FastAPI)")
    parser.add_argument("--port", type=int, default=8000, help="Port for the web UI (FastAPI)")
    parser.add_argument(
        "--public-host",
        dest="public_host",
        default=None,
        help="IP/DNS that other hospitals should use to reach this node (stored in Mongo registry)",
    )
    args = parser.parse_args()

    app = create_app(args.hospital, public_host=args.public_host)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
