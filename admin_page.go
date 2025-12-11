package main

var admin_page_content = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>APS 管理面板</title>

  <link href="/.admin/style.css" rel="stylesheet">

  <!-- IBM Plex 字体 -->
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="/.admin/ibm-plex.css" rel="stylesheet">

  <!-- Carbon Design System 样式 -->
  <link href="/.admin/carbon.css" rel="stylesheet">

</head>
<body>
  <!-- Mobile sidebar overlay -->
  <div class="mobile-sidebar-overlay" id="sidebar-overlay"></div>
  
  <!-- Mobile sidebar -->
  <div class="mobile-sidebar" id="mobile-sidebar">
    <a class="mobile-nav-item" href="#" data-tab="tab-stats">统计</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-rules">路由</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-servers">服务</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-tunnels">隧道</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-firewalls">安全</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-proxies">代理</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-users">用户</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-config">配置</a>
    <a class="mobile-nav-item" href="#" data-tab="tab-auth" style="margin-top: auto; border-top: 2px solid #525252;">登录/退出</a>
  </div>
  
  <header class="bx--header" role="banner" aria-label="APS Admin">
    <a class="bx--header__name" href="#" title="APS">APS</a>
    <button class="hamburger-btn" id="hamburger-btn" aria-label="Toggle menu">☰</button>
    <nav class="bx--header__nav" aria-label="APS 管理面板">
      <ul class="bx--header__menu-bar">
        <li><a class="bx--header__menu-item" href="#" data-tab="tab-stats">统计</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-rules">路由</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href ="#" data-tab="tab-servers">服务</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-tunnels">隧道</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-firewalls">安全</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-proxies">代理</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-users">用户</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-config">配置</a></li>
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
          <button id="btn-users-load" class="bx--btn bx--btn--secondary">加载用户</button>
          <button id="btn-users-add" class="bx--btn bx--btn--primary">新增用户</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>用户账号</th><th>管理权限</th><th>用户分组</th><th>访问令牌</th><th>操作</th></tr></thead>
            <tbody id="users-tbody"></tbody>
          </table>
        </div>
        <div id="users-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 新增用户对话框 -->
    <div data-modal id="user-add-modal" class="bx--modal" role="dialog" aria-labelledby="user-add-title">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading" id="user-add-title">新增用户</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <div class="bx--form-item"><label class="bx--label">用户账号 *</label><input id="add-user-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">登录密码 *</label><input id="add-user-password" type="password" class="bx--text-input"></div>
          <div class="bx--form-item mt-1">
            <input class="bx--toggle-input bx--toggle-input--small" id="add-user-admin" type="checkbox">
            <label class="bx--toggle-input__label" for="add-user-admin">
              管理权限
              <span class="bx--toggle__switch">
                <span class="bx--toggle__text--off" aria-hidden="true">否</span>
                <span class="bx--toggle__text--on" aria-hidden="true">是</span>
              </span>
            </label>
          </div>
          <div class="bx--form-item mt-1"><label class="bx--label">用户分组（逗号分隔）</label><input id="add-user-groups" type="text" class="bx--text-input" placeholder="groupA,groupB"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">访问令牌（可选）</label><input id="add-user-token" type="text" class="bx--text-input"></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-add-user">确认新增</button>
        </div>
      </div>
    </div>

    <!-- 编辑用户对话框 -->
    <div data-modal id="user-edit-modal" class="bx--modal" role="dialog" aria-labelledby="user-edit-title">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading" id="user-edit-title">编辑用户</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <input type="hidden" id="edit-user-original-name">
          <div class="bx--form-item"><label class="bx--label">用户账号 *</label><input id="edit-user-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">登录密码（留空表示不修改）</label><input id="edit-user-password" type="password" class="bx--text-input"></div>
          <div class="bx--form-item mt-1">
            <input class="bx--toggle-input bx--toggle-input--small" id="edit-user-admin" type="checkbox">
            <label class="bx--toggle-input__label" for="edit-user-admin">
              管理权限
              <span class="bx--toggle__switch">
                <span class="bx--toggle__text--off" aria-hidden="true">否</span>
                <span class="bx--toggle__text--on" aria-hidden="true">是</span>
              </span>
            </label>
          </div>
          <div class="bx--form-item mt-1"><label class="bx--label">用户分组（逗号分隔）</label><input id="edit-user-groups" type="text" class="bx--text-input" placeholder="groupA,groupB"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">访问令牌（可选）</label><input id="edit-user-token" type="text" class="bx--text-input"></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-user">确认保存</button>
        </div>
      </div>
    </div>

    <!-- 代理管理 -->
    <section id="tab-proxies" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="代理">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-proxies-load" class="bx--btn bx--btn--secondary">加载代理</button>
          <button id="btn-proxies-add" class="bx--btn bx--btn--primary">新增代理</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>代理名称</th><th>URLs</th><th>操作</th></tr></thead>
            <tbody id="proxies-tbody"></tbody>
          </table>
        </div>
        <div id="proxies-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 新增代理对话框 -->
    <div data-modal id="proxy-add-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">新增代理</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <div class="bx--form-item"><label class="bx--label">代理名称 *</label><input id="add-proxy-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">代理URI（每行一个或逗号分隔）*</label><textarea id="add-proxy-urls" class="bx--text-input" rows="6" placeholder="http://user:pass@host:port"></textarea></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-add-proxy">确认新增</button>
        </div>
      </div>
    </div>

    <!-- 编辑代理对话框 -->
    <div data-modal id="proxy-edit-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">编辑代理</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <input type="hidden" id="edit-proxy-original-name">
          <div class="bx--form-item"><label class="bx--label">代理名称 *</label><input id="edit-proxy-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">代理URI（每行一个或逗号分隔）*</label><textarea id="edit-proxy-urls" class="bx--text-input" rows="6" placeholder="http://user:pass@host:port"></textarea></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-proxy">确认保存</button>
        </div>
      </div>
    </div>

    <!-- 隧道管理 -->
    <section id="tab-tunnels" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="隧道">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-tunnels-load" class="bx--btn bx--btn--secondary">加载隧道</button>
          <button id="btn-tunnels-add" class="bx--btn bx--btn--primary">新增隧道</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>隧道名称</th><th>通信密码</th><th>通信服务</th><th>操作</th></tr></thead>
            <tbody id="tunnels-tbody"></tbody>
          </table>
        </div>
        <div class="mt-3">
          <h4>在线节点</h4>
          <div class="table-wrap mt-1">
            <table class="bx--data-table carbon-table">
              <thead><tr><th>节点名称</th><th>远程地址</th><th>上线时间</th><th>最后传输</th><th>延迟</th><th>请求数</th><th>错误数</th><th>QPS (平均/最小/最大)</th><th>发送字节 (总/均/最小/最大)</th><th>接收字节 (总/均/最小/最大)</th><th>响应时间 (平均/最短/最长 ms)</th></tr></thead>
              <tbody id="tunnel-endpoints-tbody"></tbody>
            </table>
          </div>
        </div>
        <div id="tunnels-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 新增隧道对话框 -->
    <div data-modal id="tunnel-add-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">新增隧道</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <div class="bx--form-item"><label class="bx--label">隧道名称 *</label><input id="add-tunnel-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">通信密码</label><input id="add-tunnel-password" type="password" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">通信服务（逗号分隔）</label><input id="add-tunnel-servers" type="text" class="bx--text-input" placeholder="serverA,serverB"></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-add-tunnel">确认新增</button>
        </div>
      </div>
    </div>

    <!-- 编辑隧道对话框 -->
    <div data-modal id="tunnel-edit-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">编辑隧道</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <input type="hidden" id="edit-tunnel-original-name">
          <div class="bx--form-item"><label class="bx--label">隧道名称 *</label><input id="edit-tunnel-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">通信密码（留空不修改）</label><input id="edit-tunnel-password" type="password" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">通信服务（逗号分隔）</label><input id="edit-tunnel-servers" type="text" class="bx--text-input" placeholder="serverA,serverB"></div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-tunnel">确认保存</button>
        </div>
      </div>
    </div>

    <!-- 服务管理 -->
    <section id="tab-servers" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="服务">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-servers-load" class="bx--btn bx--btn--secondary">加载服务</button>
          <button id="btn-servers-add" class="bx--btn bx--btn--primary">新增服务</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>服务名称</th><th>监听端口</th><th>SSL证书</th><th>安全策略</th><th>操作</th></tr></thead>
            <tbody id="servers-tbody"></tbody>
          </table>
        </div>
        <div id="servers-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 路由规则管理 -->
    <section id="tab-rules" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="路由">
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
          <button id="btn-rules-load" class="bx--btn bx--btn--secondary">加载规则</button>
          <button id="btn-rules-add" class="bx--btn bx--btn--primary">新增规则</button>
        </div>
        <div class="bx--grid bx--grid--condensed">
          <div class="bx--row">
            <div class="bx--col-lg-8">
              <div class="table-wrap">
                <table class="bx--data-table carbon-table">
                  <thead><tr><th>#</th><th>from</th><th>to</th><th>servers</th><th>操作</th></tr></thead>
                  <tbody id="rules-tbody"></tbody>
                </table>
              </div>
            </div>
            <div class="bx--col-lg-8">
              <div class="bx--form-item"><label class="bx--label">规则索引（留空=新增，填写数字=更新）</label><input id="rule-index" type="text" class="bx--text-input w-full" placeholder=""></div>
              <div class="bx--form-item mt-1"><label class="bx--label">规则 JSON</label><textarea id="rule-editor" class="code-block w-full" rows="10" spellcheck="false">{}</textarea></div>
            </div>
          </div>
        </div>
        <div id="rules-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 安全策略管理 -->
    <section id="tab-firewalls" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="安全">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-firewalls-load" class="bx--btn bx--btn--secondary">加载策略</button>
          <button id="btn-firewalls-add" class="bx--btn bx--btn--primary">新增策略</button>
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

    <!-- Server Add/Edit Modals -->
    <div data-modal id="server-add-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增服务</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">服务名称 *</label><input id="add-server-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">监听端口 *</label><input id="add-server-port" type="number" class="bx--text-input" placeholder="8080"></div><div class="bx--form-item mt-1"><label class="bx--label">SSL证书</label><input id="add-server-cert" type="text" class="bx--text-input" placeholder="auto / acme / 留空"></div><div class="bx--form-item mt-1"><label class="bx--label">安全策略</label><select id="add-server-firewall" class="bx--select"><option value="">无</option></select></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-server">确认新增</button></div></div></div>
    <div data-modal id="server-edit-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑服务</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-server-original-name"><div class="bx--form-item"><label class="bx--label">服务名称 *</label><input id="edit-server-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">监听端口 *</label><input id="edit-server-port" type="number" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">SSL证书</label><input id="edit-server-cert" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">安全策略</label><select id="edit-server-firewall" class="bx--select"><option value="">无</option></select></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-server">确认保存</button></div></div></div>

    <!-- Rule Add/Edit Modals -->
    <div data-modal id="rule-add-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增路由规则</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">规则JSON *</label><textarea id="add-rule-editor" class="code-block" rows="10" spellcheck="false">{}</textarea></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-rule">确认新增</button></div></div></div>
    <div data-modal id="rule-edit-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑路由规则</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-rule-index"><div class="bx--form-item"><label class="bx--label">规则JSON *</label><textarea id="edit-rule-editor" class="code-block" rows="10" spellcheck="false">{}</textarea></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-rule">确认保存</button></div></div></div>

    <!-- Firewall Add/Edit Modals -->
    <div data-modal id="firewall-add-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增防火墙策略</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">策略名称 *</label><input id="add-firewall-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">允许规则（每行一个CIDR或IP）</label><textarea id="add-firewall-allow" class="bx--text-input" rows="6" placeholder="192.168.1.0/24&#10;10.0.0.1"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">拒绝规则（每行一个CIDR或IP）</label><textarea id="add-firewall-block" class="bx--text-input" rows="6" placeholder="0.0.0.0/0"></textarea></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-firewall">确认新增</button></div></div></div>
    <div data-modal id="firewall-edit-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑防火墙策略</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-firewall-original-name"><div class="bx--form-item"><label class="bx--label">策略名称 *</label><input id="edit-firewall-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">允许规则（每行一个CIDR或IP）</label><textarea id="edit-firewall-allow" class="bx--text-input" rows="6"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">拒绝规则（每行一个CIDR或IP）</label><textarea id="edit-firewall-block" class="bx--text-input" rows="6"></textarea></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-firewall">确认保存</button></div></div></div>

  </main>

  <!-- Carbon JS -->
  <script src="/.admin/carbon.js"></script>
  <script src="/.admin/script.js"></script>
</body>
</html>`
