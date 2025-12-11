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
      padding-top: 48px; /* Prevent header from overlapping content */
    }
    /* Fix header to top */
    .bx--header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 8000;
      display: flex;
      align-items: center;
    }
    .bx--header__nav {
      flex: 1;
    }
    .header-auth-link {
      margin-left: auto;
      padding: 0 1rem;
      color: #f4f4f4;
      text-decoration: none;
      white-space: nowrap;
    }
    .header-auth-link:hover {
      text-decoration: underline;
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
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
      flex-wrap: wrap;
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
    /* Hamburger menu button */
    .hamburger-btn {
      display: none;
      background: none;
      border: none;
      color: white;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0.5rem;
      margin-left: auto;
    }
    /* Mobile sidebar */
    .mobile-sidebar {
      position: fixed;
      top: 48px;
      left: -280px;
      width: 280px;
      height: calc(100vh - 48px);
      background: #161616;
      transition: left 0.3s ease;
      z-index: 7999;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }
    .mobile-sidebar.open {
      left: 0;
    }
    .mobile-sidebar-overlay {
      position: fixed;
      top: 48px;
      left: 0;
      width: 100%;
      height: calc(100vh - 48px);
      background: rgba(0, 0, 0, 0.5);
      display: none;
      z-index: 7998;
    }
    .mobile-sidebar-overlay.show {
      display: block;
    }
    .mobile-nav-item {
      display: block;
      padding: 1rem;
      color: #f4f4f4;
      text-decoration: none;
      border-bottom: 1px solid #393939;
      cursor: pointer;
    }
    .mobile-nav-item:hover {
      background: #262626;
    }
    /* Auth-required items (hidden until logged in) */
    .auth-required {
      display: none !important;
    }
    .auth-required.show {
      display: block !important;
    }
    /* Mobile menu improvements */
    @media (max-width: 1055px) {
      body {
        padding-top: 48px; /* Normal padding */
      }
      .hamburger-btn {
        display: block; /* Show hamburger on mobile */
      }
      .bx--header__nav {
        display: none !important; /* Hide top nav on mobile */
      }
      .header-auth-link {
        display: none !important; /* Hide auth link in header on mobile */
      }
      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  </style>
</head>
<body>
  <!-- Mobile sidebar overlay -->
  <div class="mobile-sidebar-overlay" id="sidebar-overlay"></div>
  
  <!-- Mobile sidebar -->
  <div class="mobile-sidebar" id="mobile-sidebar">
    <a class="mobile-nav-item" href="#" data-tab="tab-stats">统计</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-users">用户</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-proxies">代理</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-tunnels">隧道</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-servers">服务</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-rules">路由</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-firewalls">安全</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-config">配置</a>
    <a class="mobile-nav-item" href="#" data-tab="tab-auth" style="margin-top: auto; border-top: 2px solid #525252;">登录/退出</a>
  </div>
  
  <header class="bx--header" role="banner" aria-label="APS Admin">
    <a class="bx--header__name" href="#" title="APS">APS</a>
    <button class="hamburger-btn" id="hamburger-btn" aria-label="Toggle menu">☰</button>
    <nav class="bx--header__nav" aria-label="APS 管理面板">
      <ul class="bx--header__menu-bar">
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-stats">统计</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-config">配置</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-users">用户</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-proxies">代理</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-tunnels">隧道</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href ="#" data-tab="tab-servers">服务</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-rules">路由</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-firewalls">安全</a></li>
      </ul>
    </nav>
    <a class="header-auth-link" href="#" data-tab="tab-auth">登录/退出</a>
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
          <input id="username" type="text" class="bx--text-input w-full" placeholder="manager">
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
          <button id="btn-users-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-users-save" class="bx--btn bx--btn--primary">保存更新</button>
          <button id="btn-users-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>用户账号</th><th>管理权限</th><th>用户分组</th><th>访问令牌</th></tr></thead>
                  <tbody id="users-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">用户账号</label><input id="user-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">登录密码</label><input id="user-password" type="text" class="bx--text-input w-full" placeholder="留空表示不修改"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">管理权限</label><select id="user-admin" class="bx--select"><option value="false">否</option><option value="true">是</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">用户分组（逗号分隔）</label><input id="user-groups" type="text" class="bx--text-input w-full" placeholder="groupA,groupB"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">访问令牌（可选）</label><input id="user-token" type="text" class="bx--text-input w-full" placeholder=""></div>
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
          <button id="btn-proxies-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-proxies-save" class="bx--btn bx--btn--primary">保存更新</button>
          <button id="btn-proxies-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>代理名称</th><th>URLs</th></tr></thead>
                  <tbody id="proxies-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">代理名称</label><input id="proxy-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">代理 URI（每行一个或逗号分隔）</label><textarea id="proxy-urls" class="bx--text-input w-full" rows="6" placeholder="http://user:pass@host:port"></textarea></div>
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
          <button id="btn-tunnels-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-tunnels-save" class="bx--btn bx--btn--primary">保存更新</button>
          <button id="btn-tunnels-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>隧道名称</th><th>通信密码</th><th>通信服务</th></tr></thead>
                  <tbody id="tunnels-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">隧道名称</label><input id="tunnel-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">通信密码</label><input id="tunnel-password" type="text" class="bx--text-input w-full" placeholder=""></div>
              <div class="bx--form-item mt-1"><label class="bx--label">通信服务（逗号分隔）</label><input id="tunnel-servers" type="text" class="bx--text-input w-full" placeholder="serverA,serverB"></div>
              
              <div class="mt-3">
                <h4>在线节点</h4>
                <div class="table-wrap mt-1">
                  <table class="bx--data-table carbon-table">
                    <thead><tr><th>节点名称</th><th>远程地址</th><th>上线时间</th><th>最后传输</th><th>延迟</th><th>请求数</th><th>错误数</th><th>QPS (平均/最小/最大)</th><th>发送字节 (总/均/最小/最大)</th><th>接收字节 (总/均/最小/最大)</th><th>响应时间 (平均/最短/最长 ms)</th></tr></thead>
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

    <!-- 服务管理 -->
    <section id="tab-servers" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="服务">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-servers-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-servers-save" class="bx--btn bx--btn--primary">保存更新</button>
          <button id="btn-servers-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>服务名称</th><th>监听端口</th><th>透明代理</th><th>公共服务</th><th>管理面板</th><th>SSL证书</th><th>安全策略</th></tr></thead>
                  <tbody id="servers-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">服务名称</label><input id="server-name" type="text" class="bx--text-input w-full"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">监听端口</label><input id="server-port" type="number" class="bx--text-input w-full" placeholder="8080"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">透明代理</label><select id="server-rawtcp" class="bx--select"><option value="">默认(false)</option><option value="true">启用</option><option value="false">禁用</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">公共服务</label><select id="server-public" class="bx--select"><option value="">默认(true)</option><option value="true">true</option><option value="false">false</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">管理面板</label><select id="server-panel" class="bx--select"><option value="">默认(false)</option><option value="true">true</option><option value="false">false</option></select></div>
              <div class="bx--form-item mt-1"><label class="bx--label">SSL证书</label><input id="server-cert" type="text" class="bx--text-input w-full" placeholder="auto / acme / 留空"></div>
              <div class="bx--form-item mt-1"><label class="bx--label">安全策略</label><select id="server-firewall" class="bx--select"><option value="">无</option></select><small>选择要绑定的防火墙规则组</small></div>
            </div>
          </div>
        </div>
        <div id="servers-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 路由规则管理 -->
    <section id="tab-rules" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="路由">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-rules-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-rules-save" class="bx--btn bx--btn--primary">保存更新</button>
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
              <div class="bx--form-item"><label class="bx--label">原始配置</label><textarea id="rule-editor" class="code-block w-full" rows="14" spellcheck="false">{}</textarea></div>
              <div class="bx--form-item mt-1"><label class="bx--label">索引（可选，更新用）</label><input id="rule-index" type="number" class="bx--text-input w-full" placeholder=""></div>
              <div class="bx--form-item mt-1">
                <label class="bx--label">安全策略（可选）</label>
                <select id="rule-firewall" class="bx--select">
                  <option value="">无</option>
                </select>
                <small>选择后会在JSON中自动添加 "firewall": "规则名称" 字段</small>
              </div>
            </div>
          </div>
        </div>
        <div id="rules-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 防火墙管理 -->
    <section id="tab-firewalls" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="安全">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-firewalls-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-firewalls-save" class="bx--btn bx--btn--primary">保存更新</button>
          <button id="btn-firewalls-delete" class="bx--btn bx--btn--danger--tertiary">删除所选</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>规则名称</th><th>模式</th><th>Allow (白名单)</th><th>Block (黑名单)</th></tr></thead>
                  <tbody id="firewalls-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">规则名称</label><input id="firewall-name" type="text" class="bx--text-input w-full" placeholder="internal_only"></div>
              <div class="bx--form-item mt-1">
                <label class="bx--label">Allow 列表 (白名单，每行一个IP/CIDR/范围)</label>
                <textarea id="firewall-allow" class="bx--text-input w-full" rows="6" placeholder="127.0.0.1&#10;192.168.0.0/16&#10;10.0.0.1-10.0.0.100"></textarea>
                <small>支持格式: 单IP (192.168.1.1), CIDR (192.168.0.0/16), 短范围 (192.168.1.1-10), 全范围 (192.168.1.1-192.168.2.10)</small>
              </div>
              <div class="bx--form-item mt-1">
                <label class="bx--label">Block 列表 (黑名单，每行一个IP/CIDR/范围)</label>
                <textarea id="firewall-block" class="bx--text-input w-full" rows="6" placeholder="111.32.1.0/24&#10;192.111.133.1"></textarea>
                <small>注意: 如果设置了Allow，则只有Allow列表中的IP可访问，Block列表将被忽略</small>
              </div>
            </div>
          </div>
        </div>
        <div id="firewalls-msg" class="mt-2"></div>
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

    // 移动端侧边栏控制
    (function() {
      function closeSidebar() {
        var sidebar = document.getElementById("mobile-sidebar");
        var overlay = document.getElementById("sidebar-overlay");
        if (sidebar) sidebar.classList.remove("open");
        if (overlay) overlay.classList.remove("show");
      }
      
      // 切换tab并自动加载数据
      function switchTab(tabId) {
        document.querySelectorAll(".bx--tab-content").forEach(function(t) { 
          t.classList.add("hidden"); 
        });
        var target = document.getElementById(tabId);
        if (target) target.classList.remove("hidden");
        
        // 自动加载对应tab的数据
        setTimeout(function() {
          if (tabId === "tab-users" && typeof loadUsers === "function") loadUsers();
          else if (tabId === "tab-proxies" && typeof loadProxies === "function") loadProxies();
          else if (tabId === "tab-tunnels" && typeof loadTunnels === "function") loadTunnels();
          else if (tabId === "tab-servers" && typeof loadServers === "function") {
            loadServers();
            if (typeof populateFirewallSelectors === "function") populateFirewallSelectors();
          }
          else if (tabId === "tab-rules" && typeof loadRules === "function") {
            loadRules();
            if (typeof populateFirewallSelectors === "function") populateFirewallSelectors();
          }
          else if (tabId === "tab-firewalls" && typeof loadFirewalls === "function") loadFirewalls();
        }, 100);
      }
      
      var hamburger = document.getElementById("hamburger-btn");
      if (hamburger) {
        hamburger.addEventListener("click", function() {
          var sidebar = document.getElementById("mobile-sidebar");
          var overlay = document.getElementById("sidebar-overlay");
          if (sidebar) sidebar.classList.toggle("open");
          if (overlay) overlay.classList.toggle("show");
        });
      }
      var overlay = document.getElementById("sidebar-overlay");
      if (overlay) overlay.addEventListener("click", closeSidebar);
      
      document.querySelectorAll(".mobile-nav-item").forEach(function(item) {
        item.addEventListener("click", function(e) {
          e.preventDefault();
          var tabId = this.getAttribute("data-tab");
          switchTab(tabId);
          closeSidebar();
        });
      });
      
      // 桌面端导航
      document.querySelectorAll(".bx--header__menu-item").forEach(function(item) {
        item.addEventListener("click", function(e) {
          e.preventDefault();
          var tabId = this.getAttribute("data-tab");
          switchTab(tabId);
        });
      });
      
      // 桌面端 Auth 链接
      var headerAuthLink = document.querySelector(".header-auth-link");
      if (headerAuthLink) {
        headerAuthLink.addEventListener("click", function(e) {
          e.preventDefault();
          var tabId = this.getAttribute("data-tab");
          switchTab(tabId);
        });
      }
    })();

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
      
      // 控制需要登录才能访问的菜单项显示/隐藏
      document.querySelectorAll(".auth-required").forEach(function(item) {
        if (isAuthed) {
          item.classList.add("show");
        } else {
          item.classList.remove("show");
        }
      });
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

    function fmtQPS(qps) {
      if (!qps || typeof qps !== 'object') return "-";
      const avg = qps.avg;
      const min = qps.min;
      const max = qps.max;
      if (avg == null || min == null || max == null) return "-";
      return fmtNum(avg) + " (min:" + fmtNum(min) + ", max:" + fmtNum(max) + ")";
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
var firewallsUrl = "/.api/firewalls";


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
      var stats = ep.stats || {};
      var bytesSent = stats.bytesSent || {};
      var bytesRecv = stats.bytesRecv || {};
      var responseTime = stats.responseTime || {};
      tr.innerHTML = "<td>" + (ep.name || "-") + "</td>" +
        "<td>" + (ep.remoteAddr || "-") + "</td>" +
        "<td>" + (ep.onlineTime || "-") + "</td>" +
        "<td>" + (ep.lastActivity || "-") + "</td>" +
        "<td>" + (stats.requestCount ?? "-") + "</td>" +
        "<td>" + (stats.errors ?? "-") + "</td>" +
        "<td>" + fmtQPS(stats.qps) + "</td>" +
        "<td>" + (bytesSent.total ?? "-") + " / " + fmtNum(bytesSent.avg) + " / " + (bytesSent.min ?? "-") + " / " + (bytesSent.max ?? "-") + "</td>" +
        "<td>" + (bytesRecv.total ?? "-") + " / " + fmtNum(bytesRecv.avg) + " / " + (bytesRecv.min ?? "-") + " / " + (bytesRecv.max ?? "-") + "</td>" +
        "<td>" + fmtNum(responseTime.avgMs) + " / " + (responseTime.minMs ?? "-") + " / " + (responseTime.maxMs ?? "-") + "</td>";
      tbody.appendChild(tr);
    });
  } catch (e) {
    var tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="12">加载失败: ' + (e.message || e) + '</td>';
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

// ===== 服务 =====
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
        "<td>" + (s.rawTCP == null ? "默认" : (s.rawTCP ? "启用" : "禁用")) + "</td>" +
        "<td>" + (s.public == null ? "默认" : (s.public ? "true" : "false")) + "</td>" +
        "<td>" + (s.panel == null ? "默认" : (s.panel ? "true" : "false")) + "</td>" +
        "<td>" + certStr + "</td>" +
        "<td>" + (s.firewall || "无") + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("server-name"); if (el) el.value = name;
        el = document.getElementById("server-port"); if (el) el.value = (s.port != null ? s.port : "");
        el = document.getElementById("server-rawtcp"); if (el) el.value = (s.rawTCP == null ? "" : (s.rawTCP ? "true" : "false"));
        el = document.getElementById("server-public"); if (el) el.value = (s.public == null ? "" : (s.public ? "true" : "false"));
        el = document.getElementById("server-panel"); if (el) el.value = (s.panel == null ? "" : (s.panel ? "true" : "false"));
        el = document.getElementById("server-cert"); if (el) el.value = (typeof s.cert === "string" ? s.cert : "");
        el = document.getElementById("server-firewall"); if (el) el.value = (s.firewall || "");
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "服务列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveServer() {
  var msg = document.getElementById("servers-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("server-name");
  var portEl = document.getElementById("server-port");
  var rawTCPEl = document.getElementById("server-rawtcp");
  var publicEl = document.getElementById("server-public");
  var panelEl = document.getElementById("server-panel");
  var certEl = document.getElementById("server-cert");
  var firewallEl = document.getElementById("server-firewall");
  var name = nameEl ? nameEl.value.trim() : "";
  var port = portEl ? parseInt(portEl.value.trim(), 10) : 0;
  var rawTCPVal = rawTCPEl ? rawTCPEl.value : "";
  var publicVal = publicEl ? publicEl.value : "";
  var panelVal = panelEl ? panelEl.value : "";
  var cert = certEl ? certEl.value.trim() : "";
  var firewall = firewallEl ? firewallEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "服务名称必填"; return; }
  if (!port || port <= 0) { if (msg) msg.textContent = "端口需为正整数"; return; }
  var payload = { port: port };
  if (rawTCPVal) payload.rawTCP = (rawTCPVal === "true");
  if (publicVal) payload.public = (publicVal === "true");
  if (panelVal) payload.panel = (panelVal === "true");
  if (cert) payload.cert = cert;
  if (firewall) payload.firewall = firewall;
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
  if (!name) { if (msg) msg.textContent = "请先选择服务"; return; }
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
    if (msg) msg.textContent = "路由列表已加载";
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

// ===== 防火墙 =====
async function loadFirewalls() {
  var msg = document.getElementById("firewalls-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(firewallsUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var tbody = document.getElementById("firewalls-tbody");
    if (tbody) tbody.innerHTML = "";
    Object.keys(data || {}).forEach(function(name){
      var fw = data[name] || {};
      var allow = fw.allow || [];
      var block = fw.block || [];
      var mode = allow.length > 0 ? "白名单" : (block.length > 0 ? "黑名单" : "无规则");
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + name + "</td>" +
        "<td>" + mode + "</td>" +
        "<td>" + allow.join(", ") + "</td>" +
        "<td>" + block.join(", ") + "</td>";
      tr.addEventListener("click", function(){
        var el;
        el = document.getElementById("firewall-name"); if (el) el.value = name;
        el = document.getElementById("firewall-allow"); if (el) el.value = allow.join("\n");
        el = document.getElementById("firewall-block"); if (el) el.value = block.join("\n");
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "防火墙规则已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}
async function saveFirewall() {
  var msg = document.getElementById("firewalls-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("firewall-name");
  var allowEl = document.getElementById("firewall-allow");
  var blockEl = document.getElementById("firewall-block");
  var name = nameEl ? nameEl.value.trim() : "";
  var allowRaw = allowEl ? allowEl.value.trim() : "";
  var blockRaw = blockEl ? blockEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "规则名称必填"; return; }
  var allow = allowRaw ? allowRaw.split("\\n").map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  var block = blockRaw ? blockRaw.split("\\n").map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  var firewall = {};
  if (allow.length > 0) firewall.allow = allow;
  if (block.length > 0) firewall.block = block;
  try {
    var res = await fetch(firewallsUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, firewall: firewall }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "保存/更新成功";
    loadFirewalls();
    populateFirewallSelectors(); // Refresh dropdowns
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}
async function deleteSelectedFirewall() {
  var msg = document.getElementById("firewalls-msg");
  if (msg) msg.textContent = "";
  var nameEl = document.getElementById("firewall-name");
  var name = nameEl ? nameEl.value.trim() : "";
  if (!name) { if (msg) msg.textContent = "请先选择/填写规则名称"; return; }
  try {
    var res = await fetch(firewallsUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadFirewalls();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// 填充防火墙下拉框
async function populateFirewallSelectors() {
  try {
    var res = await fetch(firewallsUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) return; // Silently fail if can't load firewalls
    var data = await res.json();
    var names = Object.keys(data || {});
    
    // Populate server firewall selector
    var serverFwEl = document.getElementById("server-firewall");
    if (serverFwEl) {
      serverFwEl.innerHTML = '<option value="">无</option>';
      names.forEach(function(name) {
        var opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        serverFwEl.appendChild(opt);
      });
    }
    
    // Populate rule firewall selector
    var ruleFwEl = document.getElementById("rule-firewall");
    if (ruleFwEl) {
      ruleFwEl.innerHTML = '<option value="">无</option>';
      names.forEach(function(name) {
        var opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        ruleFwEl.appendChild(opt);
      });
    }
  } catch (e) {
    // Silently fail
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

  on("btn-firewalls-load", "click", loadFirewalls);
  on("btn-firewalls-save", "click", saveFirewall);
  on("btn-firewalls-delete", "click", deleteSelectedFirewall);
})();
    // 初始加载一次
    refreshStats();
    // 填充防火墙下拉框
    populateFirewallSelectors();
  </script>
</body>
</html>`
