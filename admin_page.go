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
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-users">用户</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-proxies">代理</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-tunnels">隧道</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-servers">服务器</a></li>
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-rules">规则</a></li>
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
    <!-- 用户管理 -->
    <section id="tab-users" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="用户">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-users-load" class="bx--btn bx--btn--secondary">加载用户</button>
          <button id="btn-users-save" class="bx--btn bx--btn--primary">保存/更新用户</button>
          <button id="btn-users-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>用户名</th><th>管理员</th><th>分组</th><th>Token</th></tr></thead>
                  <tbody id="users-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">用户名</label><input id="user-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">密码</label><input id="user-password" type="text" class="bx--text-input w-full" placeholder="留空表示不修改"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">管理员</label><select id="user-admin" class="bx--select"><option value="false">否</option><option value="true">是</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">分组（逗号分隔）</label><input id="user-groups" type="text" class="bx--text-input w-full" placeholder="groupA,groupB"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">Token（可选）</label><input id="user-token" type="text" class="bx--text-input w-full" placeholder=""></div>
            </div>
          </div>
        </div>
        <div id="users-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 代理管理 -->
    <section id="tab-proxies" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="代理">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-proxies-load" class="bx--btn bx--btn--secondary">加载代理</button>
          <button id="btn-proxies-save" class="bx--btn bx--btn--primary">保存/更新代理</button>
          <button id="btn-proxies-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>代理名</th><th>URLs</th></tr></thead>
                  <tbody id="proxies-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">代理名</label><input id="proxy-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">代理 URL（每行一个或逗号分隔）</label><textarea id="proxy-urls" class="bx--text-input w-full" rows="6" placeholder="http://user:pass@host:port"></textarea></div>
            </div>
          </div>
        </div>
        <div id="proxies-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 隧道管理 -->
    <section id="tab-tunnels" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="隧道">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-tunnels-load" class="bx--btn bx--btn--secondary">加载隧道</button>
          <button id="btn-tunnels-save" class="bx--btn bx--btn--primary">保存/更新隧道</button>
          <button id="btn-tunnels-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>隧道名</th><th>Password</th><th>Servers</th></tr></thead>
                  <tbody id="tunnels-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">隧道名</label><input id="tunnel-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">密码（AES-GCM）</label><input id="tunnel-password" type="text" class="bx--text-input w-full" placeholder=""></div>
              <div class="bx--form-item mt-1"><label class="bx--label">服务器列表（逗号分隔）</label><input id="tunnel-servers" type="text" class="bx--text-input w-full" placeholder="serverA,serverB"></div>
              
              <div class="mt-3">
                <h4>在线 Endpoint</h4>
                <div class="table-wrap mt-1">
                  <table class="bx--data-table carbon-table">
                    <thead><tr><th>名称</th><th>远程地址</th><th>状态</th></tr></thead>
                    <tbody id="tunnel-endpoints-tbody"></tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div id="tunnels-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 服务器管理 -->
    <section id="tab-servers" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="服务器">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-servers-load" class="bx--btn bx--btn--secondary">加载服务器</button>
          <button id="btn-servers-save" class="bx--btn bx--btn--primary">保存/更新服务器</button>
          <button id="btn-servers-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>名称</th><th>端口</th><th>Public</th><th>Panel</th><th>Cert</th></tr></thead>
                  <tbody id="servers-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">名称</label><input id="server-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">端口</label><input id="server-port" type="number" class="bx--text-input w-full" placeholder="8080"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">Public</label><select id="server-public" class="bx--select"><option value="">默认(true)</option><option value="true">true</option><option value="false">false</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">Panel</label><select id="server-panel" class="bx--select"><option value="">默认(false)</option><option value="true">true</option><option value="false">false</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">证书（auto 或留空）</label><input id="server-cert" type="text" class="bx--text-input w-full" placeholder="auto"></div>
            </div>
          </div>
        </div>
        <div id="servers-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 规则管理 -->
    <section id="tab-rules" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="规则">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-rules-load" class="bx--btn bx--btn--secondary">加载规则</button>
          <button id="btn-rules-save" class="bx--btn bx--btn--primary">新增/更新规则</button>
          <button id="btn-rules-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>#</th><th>from</th><th>to</th><th>servers</th></tr></thead>
                  <tbody id="rules-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">规则 JSON（Mapping）</label><textarea id="rule-editor" class="code-block w-full" rows="14" spellcheck="false">{}</textarea></div>
              <div class="bx--form-item mt-1"><label class="bx--label">索引（可选，更新用）</label><input id="rule-index" type="number" class="bx--text-input w-full" placeholder=""></div>
            </div>
          </div>
        </div>
        <div id="rules-msg" class="mt-2"></div>
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

// ===== 管理 API 常量与工具 =====
var usersUrl = "/.api/users";
var proxiesUrl = "/.api/proxies";
var tunnelsUrl = "/.api/tunnels";
var serversUrl = "/.api/servers";
var rulesUrl = "/.api/rules";

function buildAuthHeaders(base) {
  var headers = base ? JSON.parse(JSON.stringify(base)) : {};
  var tokenInputEl = document.getElementById("api-token");
  var token = "";
  if (tokenInputEl && tokenInputEl.value) token = tokenInputEl.value.trim();
  if (!token && typeof authToken !== "undefined" && authToken) token = authToken;
  if (token) headers["Authorization"] = "Bearer " + token;
  return headers;
}

// ===== 用户 =====
async function loadUsers() {
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(usersUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("users-tbody");
    if (tbody) tbody.innerHTML = "";
    Object.keys(data || {}).forEach(function(name){
      var u = data[name] || {};
      var tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + name + "</td>" +
        "<td>" + (u.admin ? "是" : "否") + "</td>" +
        "<td>" + ((u.groups && u.groups.join ? u.groups.join(",") : "")) + "</td>" +
        "<td>" + (u.token || "") + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("user-name"); if (el) el.value = name;
        el = document.getElementById("user-admin"); if (el) el.value = u.admin ? "true" : "false";
        el = document.getElementById("user-groups"); if (el) el.value = (u.groups && u.groups.join ? u.groups.join(",") : "");
        el = document.getElementById("user-token"); if (el) el.value = u.token || "";
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "用户列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveUser() {
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("user-name");
  var pwdEl = document.getElementById("user-password");
  var adminEl = document.getElementById("user-admin");
  var groupsEl = document.getElementById("user-groups");
  var tokenEl = document.getElementById("user-token");
  var name = nameEl ? nameEl.value.trim() : "";
  var password = pwdEl ? pwdEl.value.trim() : "";
  var admin = adminEl ? (adminEl.value === "true") : false;
  var groups = groupsEl ? groupsEl.value.trim() : "";
  var token = tokenEl ? tokenEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "用户名必填"; return; }
  var payload = { admin: admin, token: token || undefined, groups: groups ? groups.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [] };
  if (password) payload.password = password;
  try {
    var res = await fetch(usersUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, user: payload }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "保存/更新成功";
    loadUsers();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedUser() {
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("user-name");
  var name = nameEl ? nameEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "请先选择/填写用户名"; return; }
  try {
    var res = await fetch(usersUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadUsers();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// ===== 代理 =====
async function loadProxies() {
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(proxiesUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("proxies-tbody");
    if (tbody) tbody.innerHTML = "";
    Object.keys(data || {}).forEach(function(name){
      var p = data[name] || {};
      var urls = p.urls || [];
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + name + "</td><td>" + urls.join(", ") + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("proxy-name"); if (el) el.value = name;
        el = document.getElementById("proxy-urls"); if (el) el.value = urls.join("\n");
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "代理列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveProxy() {
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("proxy-name");
  var urlsEl = document.getElementById("proxy-urls");
  var name = nameEl ? nameEl.value.trim() : "";
  var raw = urlsEl ? urlsEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "代理名必填"; return; }
  var urls = raw ? raw.split(/\n|,/).map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(proxiesUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, proxy: { urls: urls } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "保存/更新成功";
    loadProxies();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedProxy() {
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("proxy-name");
  var name = nameEl ? nameEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "请先选择代理"; return; }
  try {
    var res = await fetch(proxiesUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadProxies();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// ===== 隧道 =====
var tunnelEndpointsUrl = "/.api/tunnels/endpoints";

async function loadTunnelEndpoints(tunnelName) {
  var tbody = document.getElementById("tunnel-endpoints-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (!tunnelName) return;

  try {
    var res = await fetch(tunnelEndpointsUrl + "?tunnel=" + encodeURIComponent(tunnelName), { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    (data.endpoints || []).forEach(function(ep){
      var tr = document.createElement("tr");
      var status = ep.online ? '<span class="pill" style="background:#a7f0ba;color:#0e6027;">在线</span>' : '<span class="pill">离线</span>';
      tr.innerHTML = "<td>" + ep.name + "</td><td>" + (ep.remoteAddr || "-") + "</td><td>" + status + "</td>";
      tbody.appendChild(tr);
    });
  } catch (e) {
    var tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="4">加载失败: ' + (e.message || e) + '</td>';
    tbody.appendChild(tr);
  }
}

async function loadTunnels() {
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(tunnelsUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("tunnels-tbody");
    if (tbody) tbody.innerHTML = "";
    Object.keys(data || {}).forEach(function(name){
      var t = data[name] || {};
      var servers = t.servers || [];
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + name + "</td><td>" + (t.password ? "******" : "") + "</td><td>" + servers.join(",") + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("tunnel-name"); if (el) el.value = name;
        el = document.getElementById("tunnel-password"); if (el) el.value = t.password || "";
        el = document.getElementById("tunnel-servers"); if (el) el.value = servers.join(",");
        loadTunnelEndpoints(name);
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "隧道列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveTunnel() {
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("tunnel-name");
  var pwdEl = document.getElementById("tunnel-password");
  var serversEl = document.getElementById("tunnel-servers");
  var name = nameEl ? nameEl.value.trim() : "";
  var password = pwdEl ? pwdEl.value.trim() : "";
  var serversRaw = serversEl ? serversEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "隧道名必填"; return; }
  var servers = serversRaw ? serversRaw.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(tunnelsUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, tunnel: { password: password || undefined, servers: servers } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "保存/更新成功";
    loadTunnels();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedTunnel() {
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("tunnel-name");
  var name = nameEl ? nameEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "请先选择隧道"; return; }
  try {
    var res = await fetch(tunnelsUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadTunnels();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// ===== 服务器 =====
async function loadServers() {
  var msg = document.getElementById("servers-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(serversUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("servers-tbody");
    if (tbody) tbody.innerHTML = "";
    Object.keys(data || {}).forEach(function(name){
      var s = data[name] || {};
      var certStr = "";
      if (typeof s.cert === "string") certStr = s.cert;
      else if (s.cert && s.cert.cert) certStr = "files";
      var tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + name + "</td>" +
        "<td>" + (s.port != null ? s.port : "") + "</td>" +
        "<td>" + (s.public == null ? "默认" : (s.public ? "true" : "false")) + "</td>" +
        "<td>" + (s.panel == null ? "默认" : (s.panel ? "true" : "false")) + "</td>" +
        "<td>" + certStr + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("server-name"); if (el) el.value = name;
        el = document.getElementById("server-port"); if (el) el.value = (s.port != null ? s.port : "");
        el = document.getElementById("server-public"); if (el) el.value = (s.public == null ? "" : (s.public ? "true" : "false"));
        el = document.getElementById("server-panel"); if (el) el.value = (s.panel == null ? "" : (s.panel ? "true" : "false"));
        el = document.getElementById("server-cert"); if (el) el.value = (typeof s.cert === "string" ? s.cert : "");
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "服务器列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveServer() {
  var msg = document.getElementById("servers-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("server-name");
  var portEl = document.getElementById("server-port");
  var publicEl = document.getElementById("server-public");
  var panelEl = document.getElementById("server-panel");
  var certEl = document.getElementById("server-cert");
  var name = nameEl ? nameEl.value.trim() : "";
  var port = portEl ? parseInt(portEl.value.trim(), 10) : 0;
  var publicVal = publicEl ? publicEl.value : "";
  var panelVal = panelEl ? panelEl.value : "";
  var cert = certEl ? certEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "服务器名称必填"; return; }
  if (!port || port <= 0) { if (msg) msg.textContent = "端口需为正整数"; return; }
  var payload = { port: port };
  if (publicVal) payload.public = (publicVal === "true");
  if (panelVal) payload.panel = (panelVal === "true");
  if (cert) payload.cert = cert;
  try {
    var res = await fetch(serversUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, server: payload }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "保存/更新成功";
    loadServers();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedServer() {
  var msg = document.getElementById("servers-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("server-name");
  var name = nameEl ? nameEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "请先选择服务器"; return; }
  try {
    var res = await fetch(serversUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadServers();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// ===== 规则 =====
async function loadRules() {
  var msg = document.getElementById("rules-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(rulesUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("rules-tbody");
    if (tbody) tbody.innerHTML = "";
    for (var i = 0; i < (data || []).length; i++) {
      var m = data[i] || {};
      var fromStr = (typeof m.from === "string") ? m.from : (m.from && m.from.url ? m.from.url : "");
      var toStr = (typeof m.to === "string") ? m.to : (m.to && m.to.url ? m.to.url : "");
      var servers = m.servers;
      var serversStr = "";
      if (typeof servers === "string") serversStr = servers;
      else if (servers && servers.length) serversStr = servers.join(",");
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + i + "</td><td>" + fromStr + "</td><td>" + toStr + "</td><td>" + serversStr + "</td>";
      (function(index, mappingObj){
        tr.addEventListener("click", function(){
          var idxEl = document.getElementById("rule-index");
          var edEl = document.getElementById("rule-editor");
          if (idxEl) idxEl.value = index;
          if (edEl) edEl.value = JSON.stringify(mappingObj, null, 2);
        });
      })(i, m);
      if (tbody) tbody.appendChild(tr);
    }
    if (msg) msg.textContent = "规则列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveRule() {
  var msg = document.getElementById("rules-msg");
  if (msg) msg.textContent = "";
  var idxEl = document.getElementById("rule-index");
  var edEl = document.getElementById("rule-editor");
  var idxRaw = idxEl ? idxEl.value.trim() : "";
  var text = edEl ? edEl.value : "";
  var mapping;
  try {
    mapping = JSON.parse(text);
  } catch (e) {
    if (msg) msg.textContent = "JSON 解析失败";
    return;
  }
  var payload = { mapping: mapping };
  if (idxRaw !== "") {
    var idx = parseInt(idxRaw, 10);
    if (!isNaN(idx)) payload.index = idx;
  }
  try {
    var res = await fetch(rulesUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(payload) });
    var out = await res.text();
    if (!res.ok) throw new Error(out);
    if (msg) msg.textContent = "新增/更新成功";
    loadRules();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedRule() {
  var msg = document.getElementById("rules-msg");
  if (msg) msg.textContent = "";
  var idxEl = document.getElementById("rule-index");
  var idxRaw = idxEl ? idxEl.value.trim() : "";
  if (idxRaw === "") { if (msg) msg.textContent = "请填写要删除的索引"; return; }
  var idx = parseInt(idxRaw, 10);
  if (isNaN(idx)) { if (msg) msg.textContent = "索引必须为数字"; return; }
  try {
    var res = await fetch(rulesUrl + "?index=" + idx, { method: "DELETE", headers: buildAuthHeaders({}) });
    var out = await res.text();
    if (!res.ok) throw new Error(out);
    if (msg) msg.textContent = "删除成功";
    loadRules();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// 绑定按钮事件
(function bindMgmtEvents(){
  function on(id, evt, fn){
    var el = document.getElementById(id);
    if (el) el.addEventListener(evt, fn);
  }
  on("btn-users-load", "click", loadUsers);
  on("btn-users-save", "click", saveUser);
  on("btn-users-delete", "click", deleteSelectedUser);

  on("btn-proxies-load", "click", loadProxies);
  on("btn-proxies-save", "click", saveProxy);
  on("btn-proxies-delete", "click", deleteSelectedProxy);

  on("btn-tunnels-load", "click", loadTunnels);
  on("btn-tunnels-save", "click", saveTunnel);
  on("btn-tunnels-delete", "click", deleteSelectedTunnel);

  on("btn-servers-load", "click", loadServers);
  on("btn-servers-save", "click", saveServer);
  on("btn-servers-delete", "click", deleteSelectedServer);

  on("btn-rules-load", "click", loadRules);
  on("btn-rules-save", "click", saveRule);
  on("btn-rules-delete", "click", deleteSelectedRule);
})();
    // 初始加载一次
    refreshStats();
  </script>
</body>
</html>`
