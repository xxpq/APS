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

  <!-- Carbon Charts for time-series visualization -->
  <link href="/.admin/carbon/charts.css" rel="stylesheet">

</head>
<body>
  <!-- Mobile sidebar overlay -->
  <div class="mobile-sidebar-overlay" id="sidebar-overlay"></div>
  
  <!-- Mobile sidebar -->
  <div class="mobile-sidebar" id="mobile-sidebar">
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-stats">统计</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-rules">路由</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-servers">服务</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-tunnels">隧道</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-firewalls">安全</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-auth-providers">认证</a>
    <a class="mobile-nav-item auth-required" href="#" data-tab="tab-logs">日志</a>
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
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-stats">统计</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-rules">路由</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href ="#" data-tab="tab-servers">服务</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-tunnels">隧道</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-firewalls">安全</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-auth-providers">认证</a></li>
        <li class="auth-required"><a class="bx--header__menu-item" href="#" data-tab="tab-logs">日志</a></li>
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
        <span class="pill">刷新频率: 10s</span>
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
                  <th>接收字节 平均/最小/最大</th>
                  <th>发送字节 平均/最小/最大</th>
                  <th>响应时长 平均/最短/最长 (ms)</th>
                </tr>
              </thead>
              <tbody id="stats-tbody">
              </tbody>
            </table>
          </div>
        </div>

        <!-- 时间序列图表 -->
        <div class="mt-3">
          <div class="flex mb-2" style="align-items: center; gap: 1rem;">
            <h4 style="margin: 0;">24小时趋势</h4>
            
            <!-- 维度选择 -->
            <select id="chart-dimension" class="bx--select-input">
              <option value="global">全局统计</option>
              <option value="rules">按规则</option>
              <option value="users">按用户</option>
              <option value="servers">按服务器</option>
              <option value="tunnels">按隧道</option>
              <option value="proxies">按代理</option>
            </select>
            
            <!-- 具体项选择（动态填充） -->
            <select id="chart-dimension-key" class="bx--select-input" style="display: none;">
              <option value="">选择...</option>
            </select>
            
            <button id="btn-refresh-charts" class="bx--btn bx--btn--sm bx--btn--secondary" style="margin -left: auto;">刷新图表</button>
          </div>
          
          <div class="charts-grid">
            <div class="chart-card">
              <h5>请求数量</h5>
              <div id="chart-requests" class="chart-container"></div>
            </div>
            
            <div class="chart-card">
              <h5>流量统计 (MB)</h5>
              <div id="chart-traffic" class="chart-container"></div>
            </div>
            
            <div class="chart-card">
              <h5>活跃连接</h5>
              <div id="chart-connections" class="chart-container"></div>
            </div>
            
            <div class="chart-card">
              <h5>请求速率 (req/s)</h5>
              <div id="chart-qps" class="chart-container"></div>
            </div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-user-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-user-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-user-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-user-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-proxy-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-proxy-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-proxy-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-proxy-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-tunnel-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-tunnel-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
          <div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-tunnel-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div>
          <div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-tunnel-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div>
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
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-rules-load" class="bx--btn bx--btn--secondary">加载规则</button>
          <button id="btn-rules-add" class="bx--btn bx--btn--primary">新增规则</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>#</th><th>From</th><th>To</th><th>Servers</th><th>操作</th></tr></thead>
            <tbody id="rules-tbody"></tbody>
          </table>
        </div>
        <div id="rules-msg" class="mt-2"></div>
      </div>
    </section>


    <!-- 防火墙管理 -->
    <section id="tab-firewalls" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="安全">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-firewalls-load" class="bx--btn bx--btn--secondary">加载策略</button>
          <button id="btn-firewalls-add" class="bx--btn bx--btn--primary">新增策略</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>规则名称</th><th>模式</th><th>规则数</th><th>预览</th><th>操作</th></tr></thead>
            <tbody id="firewalls-tbody"></tbody>
          </table>
        </div>
        <div id="firewalls-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 认证提供商管理 -->
    <section id="tab-auth-providers" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="认证">
      <div class="bx--tile">
        <div class="flex mb-2">
          <button id="btn-auth-providers-load" class="bx--btn bx--btn--secondary">加载配置</button>
          <button id="btn-auth-providers-add" class="bx--btn bx--btn--primary">新增认证</button>
        </div>
        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead><tr><th>名称</th><th>认证URL</th><th>认证等级</th><th>操作</th></tr></thead>
            <tbody id="auth-providers-tbody"></tbody>
          </table>
        </div>
        <div id="auth-providers-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- 新增认证对话框 -->
    <div data-modal id="auth-provider-add-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">新增认证配置</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <div class="bx--form-item"><label class="bx--label">配置名称 *</label><input id="add-auth-provider-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">认证URL *</label><input id="add-auth-provider-url" type="text" class="bx--text-input" placeholder="http://localhost:3311/auth/*"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">认证等级</label>
            <select id="add-auth-provider-level" class="bx--select">
              <option value="0">0 - 不传递Token</option>
              <option value="1">1 - 仅传递Token</option>
              <option value="2">2 - 仅传递用户信息</option>
              <option value="3">3 - 传递Token+Hash</option>
              <option value="4">4 - 传递Token+用户信息</option>
            </select>
          </div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-add-auth-provider">确认新增</button>
        </div>
      </div>
    </div>

    <!-- 编辑认证对话框 -->
    <div data-modal id="auth-provider-edit-modal" class="bx--modal" role="dialog">
      <div class="bx--modal-container">
        <div class="bx--modal-header">
          <p class="bx--modal-header__heading">编辑认证配置</p>
          <button class="bx--modal-close" type="button" data-modal-close aria-label="关闭">
            <svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg>
          </button>
        </div>
        <div class="bx--modal-content">
          <input type="hidden" id="edit-auth-provider-original-name">
          <div class="bx--form-item"><label class="bx--label">配置名称 *</label><input id="edit-auth-provider-name" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">认证URL *</label><input id="edit-auth-provider-url" type="text" class="bx--text-input"></div>
          <div class="bx--form-item mt-1"><label class="bx--label">认证等级</label>
            <select id="edit-auth-provider-level" class="bx--select">
              <option value="0">0 - 不传递Token</option>
              <option value="1">1 - 仅传递Token</option>
              <option value="2">2 - 仅传递用户信息</option>
              <option value="3">3 - 传递Token+Hash</option>
              <option value="4">4 - 传递Token+用户信息</option>
            </select>
          </div>
        </div>
        <div class="bx--modal-footer">
          <button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button>
          <button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-auth-provider">确认保存</button>
        </div>
      </div>
    </div>

    <!-- 日志管理 -->
    <section id="tab-logs" class="bx--tab-content hidden" role="tabpanel" aria-labelledby="日志">
      <div class="bx--tile">
        <div class="flex mb-2" style="flex-wrap: wrap; gap: 0.5rem; align-items: flex-end;">
          <div class="bx--form-item">
            <label class="bx--label">开始时间</label>
            <input id="logs-start-time" type="datetime-local" class="bx--text-input bx--text-input--sm">
          </div>
          <div class="bx--form-item">
            <label class="bx--label">结束时间</label>
            <input id="logs-end-time" type="datetime-local" class="bx--text-input bx--text-input--sm">
          </div>
          <div class="bx--form-item">
            <label class="bx--label">协议</label>
            <input id="logs-protocols" type="text" class="bx--text-input bx--text-input--sm" placeholder="http,https,rawtcp">
          </div>
          <div class="bx--form-item">
            <label class="bx--label">服务器</label>
            <input id="logs-servers" type="text" class="bx--text-input bx--text-input--sm" placeholder="Server Name">
          </div>
          <div class="bx--form-item" style="flex-grow: 1;">
             <button id="btn-logs-search" class="bx--btn bx--btn--primary bx--btn--sm">查询</button>
             <button id="btn-logs-delete" class="bx--btn bx--btn--danger bx--btn--sm">批量删除</button>
          </div>
        </div>
        <div class="flex mb-2" style="flex-wrap: wrap; gap: 0.5rem;">
           <!-- 更多过滤条件 -->
           <input id="logs-tunnels" type="text" class="bx--text-input bx--text-input--sm" placeholder="Tunnel">
           <input id="logs-proxies" type="text" class="bx--text-input bx--text-input--sm" placeholder="Proxy">
           <input id="logs-users" type="text" class="bx--text-input bx--text-input--sm" placeholder="User">
           <input id="logs-firewalls" type="text" class="bx--text-input bx--text-input--sm" placeholder="Firewall">
        </div>

        <div class="table-wrap">
          <table class="bx--data-table carbon-table">
            <thead>
              <tr>
                <th><input type="checkbox" id="logs-select-all" /></th>
                <th>时间</th>
                <th>协议</th>
                <th>方法</th>
                <th>URL / 目标</th>
                <th>状态码</th>
                <th>耗时(ms)</th>
                <th>大小(入/出)</th>
                <th>客户端IP</th>
                <th>用户</th>
                <th>Token</th>
                <th>详情</th>
              </tr>
            </thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
        
        <div class="flex mt-2" style="justify-content: space-between; align-items: center;">
           <div id="logs-pagination-info">Page 1</div>
           <div>
             <button id="btn-logs-prev" class="bx--btn bx--btn--secondary bx--btn--sm">上一页</button>
             <button id="btn-logs-next" class="bx--btn bx--btn--secondary bx--btn--sm">下一页</button>
           </div>
        </div>
        <div id="logs-msg" class="mt-2"></div>
      </div>
    </section>

    <!-- Server Add/Edit Modals -->
    <div data-modal id="server-add-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增服务</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">服务名称 *</label><input id="add-server-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">监听端口 *</label><input id="add-server-port" type="number" class="bx--text-input" placeholder="8080"></div><div class="bx--form-item mt-1"><label class="bx--label">SSL证书</label><select id="add-server-cert" class="bx--select"><option value="">无</option><option value="auto">Auto</option><option value="acme">ACME</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">安全策略</label><select id="add-server-firewall" class="bx--select"><option value="">无</option></select></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="add-server-rawtcp" type="checkbox" class="bx--checkbox"><label for="add-server-rawtcp" class="bx--checkbox-label"><span class="bx--checkbox-label-text">透明代理</span></label></div></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="add-server-public" type="checkbox" class="bx--checkbox"><label for="add-server-public" class="bx--checkbox-label"><span class="bx--checkbox-label-text">公共服务</span></label></div></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="add-server-panel" type="checkbox" class="bx--checkbox"><label for="add-server-panel" class="bx--checkbox-label"><span class="bx--checkbox-label-text">管理面板</span></label></div></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-server-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-server-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-server">确认新增</button></div></div></div>
    <div data-modal id="server-edit-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑服务</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-server-original-name"><div class="bx--form-item"><label class="bx--label">服务名称 *</label><input id="edit-server-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">监听端口 *</label><input id="edit-server-port" type="number" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">SSL证书</label><select id="edit-server-cert" class="bx--select"><option value="">无</option><option value="auto">Auto</option><option value="acme">ACME</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">安全策略</label><select id="edit-server-firewall" class="bx--select"><option value="">无</option></select></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="edit-server-rawtcp" type="checkbox" class="bx--checkbox"><label for="edit-server-rawtcp" class="bx--checkbox-label"><span class="bx--checkbox-label-text">透明代理</span></label></div></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="edit-server-public" type="checkbox" class="bx--checkbox"><label for="edit-server-public" class="bx--checkbox-label"><span class="bx--checkbox-label-text">公共服务</span></label></div></div><div class="bx--form-item mt-1"><div class="bx--checkbox-wrapper"><input id="edit-server-panel" type="checkbox" class="bx--checkbox"><label for="edit-server-panel" class="bx--checkbox-label"><span class="bx--checkbox-label-text">管理面板</span></label></div></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-server-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-server-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-server">确认保存</button></div></div></div>



    <!-- Rule Add/Edit Modals -->
    <div data-modal id="rule-add-modal" class="bx--modal"><div class="bx--modal-container" style="max-width: 600px;"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增路由规则</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">源路径 (From) *</label><textarea id="add-rule-from" class="bx--text-input" rows="2" placeholder="/api/*&#10;或多行URL"></textarea><div class="bx--form__helper-text">支持单个URL或多个URL（每行一个）</div></div><div class="bx--form-item mt-1"><label class="bx--label">目标路径 (To) *</label><input id="add-rule-to" type="text" class="bx--text-input" placeholder="http://backend/*"></div><div class="bx--form-item mt-1"><label class="bx--label">Via Endpoints (可选)</label><input id="add-rule-via-endpoints" type="text" class="bx--text-input" placeholder="endpoint_name"><div class="bx--form__helper-text">通过指定的端点转发</div></div><div class="bx--form-item mt-1"><label class="bx--label">认证绑定 (可选)</label><select id="add-rule-auth-provider" class="bx--select"><option value="">无</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">服务器列表 (可选)</label><input id="add-rule-servers" type="text" class="bx--text-input" placeholder="server1, server2"><div class="bx--form__helper-text">多个服务器用逗号分隔</div></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-rule-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-rule-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-rule">确认新增</button></div></div></div>
    <div data-modal id="rule-edit-modal" class="bx--modal"><div class="bx--modal-container" style="max-width: 600px;"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑路由规则</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-rule-index"><div class="bx--form-item"><label class="bx--label">源路径 (From) *</label><textarea id="edit-rule-from" class="bx--text-input" rows="2"></textarea><div class="bx--form__helper-text">支持单个URL或多个URL（每行一个）</div></div><div class="bx--form-item mt-1"><label class="bx--label">目标路径 (To) *</label><input id="edit-rule-to" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">Via Endpoints (可选)</label><input id="edit-rule-via-endpoints" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">认证绑定 (可选)</label><select id="edit-rule-auth-provider" class="bx--select"><option value="">无</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">服务器列表 (可选)</label><input id="edit-rule-servers" type="text" class="bx--text-input"><div class="bx--form__helper-text">多个服务器用逗号分隔</div></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-rule-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-rule-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-rule">确认保存</button></div></div></div>



    <!-- Firewall Add/Edit Modals -->
    <div data-modal id="firewall-add-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">新增防火墙策略</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><div class="bx--form-item"><label class="bx--label">策略名称 *</label><input id="add-firewall-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">允许规则（每行一个CIDR或IP）</label><textarea id="add-firewall-allow" class="bx--text-input" rows="6" placeholder="192.168.1.0/24&#10;10.0.0.1"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">拒绝规则（每行一个CIDR或IP）</label><textarea id="add-firewall-block" class="bx--text-input" rows="6" placeholder="0.0.0.0/0"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="add-firewall-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="add-firewall-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-add-firewall">确认新增</button></div></div></div>
    <div data-modal id="firewall-edit-modal" class="bx--modal"><div class="bx--modal-container"><div class="bx--modal-header"><p class="bx--modal-header__heading">编辑防火墙策略</p><button class="bx--modal-close" type="button" data-modal-close aria-label="关闭"><svg class="bx--modal-close__icon" width="16" height="16" viewBox="0 0 16 16"><path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/></svg></button></div><div class="bx--modal-content"><input type="hidden" id="edit-firewall-original-name"><div class="bx--form-item"><label class="bx--label">策略名称 *</label><input id="edit-firewall-name" type="text" class="bx--text-input"></div><div class="bx--form-item mt-1"><label class="bx--label">允许规则（每行一个CIDR或IP）</label><textarea id="edit-firewall-allow" class="bx--text-input" rows="6"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">拒绝规则（每行一个CIDR或IP）</label><textarea id="edit-firewall-block" class="bx--text-input" rows="6"></textarea></div><div class="bx--form-item mt-1"><label class="bx--label">日志等级</label><select id="edit-firewall-log-level" class="bx--select"><option value="">继承默认</option><option value="0">0 - 不记录</option><option value="1">1 - 基础信息</option><option value="2">2 - 完整请求</option></select></div><div class="bx--form-item mt-1"><label class="bx--label">日志保留 (小时)</label><input id="edit-firewall-log-retention" type="number" class="bx--text-input" placeholder="继承默认"></div></div><div class="bx--modal-footer"><button class="bx--btn bx--btn--secondary" type="button" data-modal-close>取消</button><button class="bx--btn bx--btn--primary" type="button" id="confirm-edit-firewall">确认保存</button></div></div></div>

  </main>

  <!-- Carbon JS -->
  <script src="/.admin/carbon.js"></script>
  <!-- Carbon Charts JS -->
  <script src="/.admin/carbon/charts.js"></script>

  <script src="/.admin/script.js"></script>
</body>
</html>`
