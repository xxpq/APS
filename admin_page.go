package main

var admin_page_content = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>APS 管理面板</title>

  <!-- IBM Plex 字体 -->
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/ibm-plex/6.0.0/css/ibm-plex.min.css" rel="stylesheet">

  <!-- Carbon Design System 样式 -->
  <link href="https://unpkg.com/carbon-components@10.58.14/css/carbon-components.min.css" rel="stylesheet">

  <style>
    :root {
      --bg: #f4f4f4;
    }
    body {
      font-family: "IBM Plex Sans", system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      background: var(--bg);
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1rem;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }
    .status-line {
      font-size: 0.875rem;
      color: #525252;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }
    .code-block {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.85rem;
      background: #161616;
      color: #f4f4f4;
      border-radius: 0.25rem;
      padding: 0.75rem;
      white-space: pre;
      overflow: auto;
    }
    .flex {
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }
    .mt-1 { margin-top: 0.5rem; }
    .mt-2 { margin-top: 1rem; }
    .mt-3 { margin-top: 1.5rem; }
    .mb-1 { margin-bottom: 0.5rem; }
    .mb-2 { margin-bottom: 1rem; }
    .mb-3 { margin-bottom: 1.5rem; }
    .w-full { width: 100%; }
    .hidden { display: none; }
    .table-wrap {
      overflow: auto;
      max-height: 400px;
      border: 1px solid #e0e0e0;
      border-radius: 4px;
    }
    .carbon-table {
      width: 100%;
    }
    .pill {
      padding: 0 8px;
      border-radius: 999px;
      background: #e0e0e0;
      display: inline-block;
      font-size: 12px;
      color: #161616;
    }
  </style>
</head>
<body>
  <header class="bx--header" role="banner" aria-label="APS Admin">
    <a class="bx--header__name" href="#" title="APS">APS</a>
    <nav class="bx--header__nav" aria-label="APS 管理面板">
      <ul class="bx--header__menu-bar">
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-stats">统计</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-config">配置</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-auth">登录/退出</a></li>
      </ul>
    </nav>
  </header>

  <main class="container">
    <div class="header">
      <h2>APS 管理面板</h2>
      <div class="status-line">
        <span id="auth-status" class="pill">未登录</span>
        <span class="pill">刷新频率: 1s</span>
        <span class="pill"><a href="/.ssl" target="_blank" style="text-decoration:none;color:inherit;">证书安装</a></span>
      </div>
    </div>

    <!-- 统计面板 -->
    <section id="tab-stats" class="bx--tab-content" role="tabpanel" aria-labelledby="统计">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-refresh-now" class="bx--btn bx--btn--secondary">立即刷新</button>
          <button id="btn-toggle-auto" class="bx--btn bx--btn--tertiary">暂停自动刷新</button>
        </div>

        <div class="stats-grid">
          <div class="bx--tile">
            <h4>总请求</h4>
            <div id="stat-totalRequests">-</div>
          </div>
          <div class="bx--tile">
            <h4>活跃连接</h4>
            <div id="stat-activeConnections">-</div>
          </div>
          <div class="bx--tile">
            <h4>发送字节</h4>
            <div id="stat-totalBytesSent">-</div>
          </div>
          <div class="bx--tile">
            <h4>接收字节</h4>
            <div id="stat-totalBytesRecv">-</div>
          </div>
        </div>

        <div class="mt-3">
          <h4>维度统计</h4>
          <div class="table-wrap mt-1">
            <table class="bx--data-table carbon-table" id="stats-table">
              <thead>
                <tr>
                  <th>维度</th>
                  <th>键名</th>
                  <th>请求数</th>
                  <th>错误数</th>
                  <th>QPS</th>
                  <th>请求包平均/最小/最大</th>
                  <th>响应包平均/最小/最大</th>
                  <th>响应时长 平均/最短/最长 (ms)</th>
                </tr>
              </thead>
              <tbody id="stats-tbody">
              </tbody>
            </table>
          </div>
        </div>

        <div class="mt-3">
          <h4>原始数据</h4>
          <div id="stats-raw" class="code-block">{}</div>
        </div>
      </div>
    </section>

    <!-- 配置编辑器 -->
    <section id="tab-config" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="配置">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-load-config" class="bx--btn bx--btn--secondary">读取配置</button>
          <button id="btn-save-config" class="bx--btn bx--btn--primary">保存配置</button>
        </div>
        <div class="mb-1">注意：保存会触发后端热重载</div>
        <textarea id="config-editor" class="code-block w-full" rows="24" spellcheck="false">{}</textarea>
        <div id="config-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 登录/退出 -->
    <section id="tab-auth" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="认证">
      <div class="bx--tile">
        <div class="bx--form-item">
          <label for="username" class="bx--label">用户名</label>
          <input id="username" type="text" class="bx--text-input w-full" placeholder="admin">
        </div>
        <div class="bx--form-item mt-1">
          <label for="password" class="bx--label">密码</label>
          <input id="password" type="password" class="bx--text-input w-full" placeholder="••••••">
        </div>
        <div class="flex mt-2">
          <button id="btn-login" class="bx--btn bx--btn--primary">登录</button>
          <button id="btn-logout" class="bx--btn bx--btn--danger--tertiary">退出登录</button>
        </div>

        <div class="mt-2">
          <div class="bx--form-item">
            <label class="bx--label">API Token（可选，Authorization: Bearer）</label>
            <input id="api-token" type="text" class="bx--text-input w-full" placeholder="从 config.json 的 users[].token 读取或登录返回">
          </div>
          <div class="mt-1">
            <small>提示：登录成功会下发 HttpOnly Cookie（APS-Admin-Token）。也可将 token 放到输入框以便配置编辑器使用 Authorization 头。</small>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Carbon JS -->
  <script src="https://unpkg.com/carbon-components@10.58.14/scripts/carbon-components.min.js"></script>

  <script>
    // 简易状态
    let autoRefresh = true;
    let authToken = ""; // Authorization: Bearer
    const statsUrl = "/.api/stats";
    const configUrl = "/.api/config";
    const loginUrl = "/.api/login";
    const logoutUrl = "/.api/logout";

    // Tab 切换
    document.querySelectorAll(".bx--header__menu-item").forEach(a => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const tabId = a.getAttribute("data-tab");
        document.querySelectorAll("section.bx--tab-content").forEach(s => s.classList.add("hidden"));
        document.getElementById(tabId).classList.remove("hidden");
      });
    });

    // 登录/退出
    document.getElementById("btn-login").addEventListener("click", async () => {
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value.trim();
      try {
        const res = await fetch(loginUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        });
        if (!res.ok) {
          const text = await res.text();
          throw new Error("登录失败: " + text);
        }
        const data = await res.json();
        // 后端会设置 HttpOnly Cookie，这里可选保存 token 用于 Authorization 请求
        if (data && data.token) {
          authToken = data.token;
          document.getElementById("api-token").value = data.token;
        }
        setAuthStatus(true);
      } catch (err) {
        alert(err.message || err);
      }
    });

    document.getElementById("btn-logout").addEventListener("click", async () => {
      try {
        const headers = {};
        const tokenInput = document.getElementById("api-token").value.trim();
        const token = tokenInput || authToken;
        if (token) headers["Authorization"] = "Bearer " + token;

        const res = await fetch(logoutUrl, { method: "POST", headers });
        if (!res.ok) {
          const text = await res.text();
          throw new Error("退出失败: " + text);
        }
        authToken = "";
        document.getElementById("api-token").value = "";
        setAuthStatus(false);
      } catch (err) {
        alert(err.message || err);
      }
    });

    function setAuthStatus(isAuthed) {
      const el = document.getElementById("auth-status");
      el.textContent = isAuthed ? "已登录" : "未登录";
      el.style.background = isAuthed ? "#a7f0ba" : "#e0e0e0";
      el.style.color = isAuthed ? "#0e6027" : "#161616";
    }

    // 配置读取/保存
    document.getElementById("btn-load-config").addEventListener("click", loadConfig);
    document.getElementById("btn-save-config").addEventListener("click", saveConfig);

    async function loadConfig() {
      const msg = document.getElementById("config-msg");
      msg.textContent = "";
      try {
        const headers = {};
        const tokenInput = document.getElementById("api-token").value.trim();
        const token = tokenInput || authToken;
        if (token) headers["Authorization"] = "Bearer " + token;

        const res = await fetch(configUrl, { headers });
        if (!res.ok) {
          const text = await res.text();
          throw new Error("读取配置失败: " + text);
        }
        const data = await res.json();
        document.getElementById("config-editor").value = JSON.stringify(data, null, 2);
        msg.textContent = "配置已加载";
      } catch (err) {
        msg.textContent = err.message || err;
      }
    }

    async function saveConfig() {
      const msg = document.getElementById("config-msg");
      msg.textContent = "";
      try {
        const headers = { "Content-Type": "application/json" };
        const tokenInput = document.getElementById("api-token").value.trim();
        const token = tokenInput || authToken;
        if (token) headers["Authorization"] = "Bearer " + token;

        const text = document.getElementById("config-editor").value;
        let obj;
        try {
          obj = JSON.parse(text);
        } catch (e) {
          throw new Error("JSON 解析失败，请检查格式");
        }
        const res = await fetch(configUrl, { method: "POST", headers, body: JSON.stringify(obj) });
        const out = await res.text();
        if (!res.ok) {
          throw new Error("保存失败: " + out);
        }
        msg.textContent = "保存成功，已触发热重载";
      } catch (err) {
        msg.textContent = err.message || err;
      }
    }

    // 统计自动刷新
    let statsTimer = null;
    function startAutoRefresh() {
      if (statsTimer) clearInterval(statsTimer);
      statsTimer = setInterval(() => { if (autoRefresh) refreshStats(); }, 1000);
    }
    startAutoRefresh();

    document.getElementById("btn-refresh-now").addEventListener("click", refreshStats);
    document.getElementById("btn-toggle-auto").addEventListener("click", () => {
      autoRefresh = !autoRefresh;
      document.getElementById("btn-toggle-auto").textContent = autoRefresh ? "暂停自动刷新" : "恢复自动刷新";
    });

    async function refreshStats() {
      try {
        const res = await fetch(statsUrl);
        if (!res.ok) {
          const text = await res.text();
          throw new Error("获取统计失败: " + text);
        }
        const stats = await res.json();
        renderStatsSummary(stats);
        renderStatsTable(stats);
        renderRaw(stats);
      } catch (err) {
        console.warn(err.message || err);
      }
    }

    function renderStatsSummary(stats) {
      setText("stat-totalRequests", stats.totalRequests);
      setText("stat-activeConnections", stats.activeConnections);
      setText("stat-totalBytesSent", stats.totalBytesSent);
      setText("stat-totalBytesRecv", stats.totalBytesRecv);
    }

    function setText(id, v) {
      const el = document.getElementById(id);
      if (el) el.textContent = v == null ? "-" : String(v);
    }

    function renderStatsTable(stats) {
      const tbody = document.getElementById("stats-tbody");
      tbody.innerHTML = "";

      const dims = [
        ["rules", stats.rules],
        ["users", stats.users],
        ["servers", stats.servers],
        ["tunnels", stats.tunnels],
        ["proxies", stats.proxies],
      ];

      for (const [dim, map] of dims) {
        if (!map) continue;
        for (const key of Object.keys(map)) {
          const m = map[key];
          const tr = document.createElement("tr");
          tr.innerHTML = ` + "`" + `
            <td>${dim}</td>
            <td>${key}</td>
            <td>${m.requestCount ?? "-"}</td>
            <td>${m.errors ?? "-"}</td>
            <td>${fmtNum(m.qps)}</td>
            <td>${fmtNum(m.bytesRecv?.avg)} / ${m.bytesRecv?.min ?? "-"} / ${m.bytesRecv?.max ?? "-"}</td>
            <td>${fmtNum(m.bytesSent?.avg)} / ${m.bytesSent?.min ?? "-"} / ${m.bytesSent?.max ?? "-"}</td>
            <td>${fmtNum(m.responseTime?.avgMs)} / ${m.responseTime?.minMs ?? "-"} / ${m.responseTime?.maxMs ?? "-"}</td>
          ` + "`" + `;
          tbody.appendChild(tr);
        }
      }
    }

    function fmtNum(n) {
      if (n == null || isNaN(n)) return "-";
      if (typeof n === "number") {
        if (!Number.isInteger(n)) return n.toFixed(2);
      }
      return String(n);
    }

    function renderRaw(stats) {
      const el = document.getElementById("stats-raw");
      el.textContent = JSON.stringify(stats, null, 2);
    }

    // 初始加载一次
    refreshStats();
  </script>
</body>
</html>`
