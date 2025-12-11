package main

var admin_page_js = `
    // 简易状态
    let autoRefresh = true;
    let authToken = ""; // Authorization: Bearer
    const statsUrl = "/.api/stats";
    const configUrl = "/.api/config";
    const loginUrl = "/.api/login";
    const logoutUrl = "/.api/logout";

    // Cookie 工具函数
    function setCookie(name, value, days) {
      let expires = "";
      if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
      }
      document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Strict";
    }

    function getCookie(name) {
      const nameEQ = name + "=";
      const ca = document.cookie.split(';');
      for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
      }
      return null;
    }

    function deleteCookie(name) {
      document.cookie = name + '=; Max-Age=-99999999; path=/; SameSite=Strict';
    }

    // Wait for DOM to be ready
    document.addEventListener("DOMContentLoaded", function() {
      
      // Tab 切换
      document.querySelectorAll(".bx--header__menu-item").forEach(a => {
        a.addEventListener("click", (e) => {
          e.preventDefault();
          const tabId = a.getAttribute("data-tab");
          document.querySelectorAll("section.bx--tab-content").forEach(s => s.classList.add("hidden"));
          document.getElementById(tabId).classList.remove("hidden");
        });
      });

    // Helper functions
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
    
    // 移动端侧边栏控制
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

    // 页面加载时检查登录状态
    const savedToken = getCookie("aps-auth-token");
    const isLoggedIn = getCookie("aps-logged-in");
    if (savedToken && isLoggedIn === "true") {
      authToken = savedToken;
      document.getElementById("api-token").value = savedToken;
      setAuthStatus(true);
    }

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
          // 保存登录状态到cookie (7天有效期)
          setCookie("aps-auth-token", data.token, 7);
          setCookie("aps-logged-in", "true", 7);
        }
        setAuthStatus(true);
        showNotification('success', '登录成功', '欢迎回来!');
      } catch (err) {
        showNotification('error', '登录失败', err.message || err);
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
        // 删除登录状态cookie
        deleteCookie("aps-auth-token");
        deleteCookie("aps-logged-in");
        setAuthStatus(false);
        showNotification('success', '退出成功', '已退出登录');
      } catch (err) {
        showNotification('error', '退出失败', err.message || err);
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

// ===== Notification \u901a\u77e5\u7cfb\u7edf =====
function showNotification(type, title, subtitle) {
  var container = document.getElementById('notification-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'notification-container';
    container.style.position = 'fixed';
    container.style.top = '3rem';
    container.style.right = '1rem';
    container.style.zIndex = '9999';
    container.style.maxWidth = '400px';
    document.body.appendChild(container);
  }

  var notification = document.createElement("div");
  notification.className = "bx--inline-notification bx--inline-notification--" + type;
  notification.setAttribute("role", "alert");
  notification.style.marginBottom = '0.5rem';
  
  var iconPath = '';
  if (type === 'success') iconPath = 'M14 1a1 1 0 011 1v12a1 1 0 01-1 1H2a1 1 0 01-1-1V2a1 1 0 011-1h12zm0 1H2v12h12V2zm-2.5 7.5l-3 3-1.5-1.5-.7.7 2.2 2.2 3.7-3.7-.7-.7z';
  else if (type === 'error') iconPath = 'M8 1C4.1 1 1 4.1 1 8s3.1 7 7 7 7-3.1 7-7-3.1-7-7-7zm3.5 9.5l-1 1L8 9l-2.5 2.5-1-1L7 8 4.5 5.5l1-1L8 7l2.5-2.5 1 1L9 8l2.5 2.5z';
  else if (type === 'warning') iconPath = 'M8 1l7 14H1L8 1zm0 3L3.2 13h9.6L8 4zm0 6h.5v2H7.5V10H8zm0-5h.5v4H7.5V5H8z';
  else iconPath = 'M8 1C4.1 1 1 4.1 1 8s3.1 7 7 7 7-3.1 7-7-3.1-7-7-7zm0 13c-3.3 0-6-2.7-6-6s2.7-6 6-6 6 2.7 6 6-2.7 6-6 6zm-.5-7H8v5H7.5V7zm0-2H8v1H7.5V5z';

  notification.innerHTML = 
    '<div class="bx--inline-notification__details">' +
      '<svg class="bx--inline-notification__icon" width="16" height="16" viewBox="0 0 16 16">' +
        '<path d="' + iconPath + '"/>' +
      '</svg>' +
      '<div class="bx--inline-notification__text-wrapper">' +
        '<p class="bx--inline-notification__title">' + title + '</p>' +
        (subtitle ? '<p class="bx--inline-notification__subtitle">' + subtitle + '</p>' : '') +
      '</div>' +
    '</div>' +
    '<button class="bx--inline-notification__close-button" type="button" aria-label="\u5173\u95ed">' +
      '<svg class="bx--inline-notification__close-icon" width="16" height="16" viewBox="0 0 16 16">' +
        '<path d="M12 4.7L11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3 4.7 12 8 8.7 11.3 12 12 11.3 8.7 8z"/>' +
      '</svg>' +
    '</button>';

  container.appendChild(notification);
  
  var closeBtn = notification.querySelector('.bx--inline-notification__close-button');
  if (closeBtn) {
    closeBtn.addEventListener('click', function() {
      notification.remove();
    });
  }
  
  setTimeout(function() {
    if (notification.parentNode) notification.remove();
  }, 5000);
}


// ===== 用户 =====
// Carbon Modal实例
var userAddModal, userEditModal;

// 初始化Carbon Modal
function initUserModals() {
  // 手动处理Modal关闭按钮
  var addModal = document.querySelector('#user-add-modal');
  var editModal = document.querySelector('#user-edit-modal');
  
  if (addModal) {
    addModal.addEventListener('click', function(e) {
      if (e.target.closest('[data-modal-close]')) {
        addModal.classList.remove('is-visible');
      }
    });
  }
  
  if (editModal) {
    editModal.addEventListener('click', function(e) {
      if (e.target.closest('[data-modal-close]')) {
        editModal.classList.remove('is-visible');
      }
    });
  }
  
  // 尝试使用Carbon组件API
  if (typeof CarbonComponents !== 'undefined' && CarbonComponents.Modal) {
    if (addModal && !userAddModal) userAddModal = CarbonComponents.Modal.create(addModal);
    if (editModal && !userEditModal) userEditModal = CarbonComponents.Modal.create(editModal);
  }
}

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
        "<td>" + (u.token || "") + "</td>" +
        "<td><button class='bx--btn bx--btn--sm bx--btn--ghost' onclick='openEditUserModal(\"" + name.replace(/"/g, '&quot;') + "\")'\u003e编辑</button> " +
        "<button class='bx--btn bx--btn--sm bx--btn--danger--ghost' onclick='deleteUser(\"" + name.replace(/"/g, '&quot;') + "\")'\u003e删除</button></td>";
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "用户列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}

function openAddUserModal() {
  document.getElementById("add-user-name").value = "";
  document.getElementById("add-user-password").value = "";
  document.getElementById("add-user-admin").checked = false;
  document.getElementById("add-user-groups").value = "";
  document.getElementById("add-user-token").value = "";
  var modal = document.querySelector('#user-add-modal');
  if (modal) modal.classList.add('is-visible');
}

async function openEditUserModal(username) {
  try {
    var res = await fetch(usersUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var u = data[username] || {};
    
    document.getElementById("edit-user-original-name").value = username;
    document.getElementById("edit-user-name").value = username;
    document.getElementById("edit-user-password").value = "";
    document.getElementById("edit-user-admin").checked = !!u.admin;
    document.getElementById("edit-user-groups").value = (u.groups && u.groups.join ? u.groups.join(",") : "");
    document.getElementById("edit-user-token").value = u.token || "";
    
    var modal = document.querySelector('#user-edit-modal');
    if (modal) modal.classList.add('is-visible');
  } catch (e) {
    var msg = document.getElementById("users-msg");
    if (msg) msg.textContent = "加载用户数据失败: " + (e.message || e);
  }
}

async function confirmAddUser() {
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("add-user-name").value.trim();
  var password = document.getElementById("add-user-password").value.trim();
  var admin = document.getElementById("add-user-admin").checked;
  var groups = document.getElementById("add-user-groups").value.trim();
  var token = document.getElementById("add-user-token").value.trim();
  
  if (!name) { if (msg) msg.textContent = "用户名必填"; return; }
  if (!password) { if (msg) msg.textContent = "密码必填"; return; }
  
  var payload = { 
    admin: admin, 
    password: password,
    token: token || undefined, 
    groups: groups ? groups.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [] 
  };
  
  try {
    var res = await fetch(usersUrl, { 
      method: "POST", 
      headers: buildAuthHeaders({ "Content-Type": "application/json" }), 
      body: JSON.stringify({ name: name, user: payload }) 
    });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "新增成功";
    var modal = document.querySelector('#user-add-modal');
    if (modal) modal.classList.remove('is-visible');
    loadUsers();
  } catch (e) {
    if (msg) msg.textContent = "新增失败: " + (e.message || e);
  }
}

async function confirmEditUser() {
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("edit-user-name").value.trim();
  var password = document.getElementById("edit-user-password").value.trim();
  var admin = document.getElementById("edit-user-admin").checked;
  var groups = document.getElementById("edit-user-groups").value.trim();
  var token = document.getElementById("edit-user-token").value.trim();
  
  if (!name) { if (msg) msg.textContent = "用户名必填"; return; }
  
  var payload = { 
    admin: admin, 
    token: token || undefined, 
    groups: groups ? groups.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [] 
  };
  // 只有密码非空时才包含在payload中
  if (password && password.length > 0) payload.password = password;
  
  try {
    var res = await fetch(usersUrl, { 
      method: "POST", 
      headers: buildAuthHeaders({ "Content-Type": "application/json" }), 
      body: JSON.stringify({ name: name, user: payload }) 
    });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "更新成功";
    var modal = document.querySelector('#user-edit-modal');
    if (modal) modal.classList.remove('is-visible');
    loadUsers();
  } catch (e) {
    if (msg) msg.textContent = "更新失败: " + (e.message || e);
  }
}

async function deleteUser(username) {
  if (!confirm("确定要删除用户 '" + username + "' 吗?")) return;
  
  var msg = document.getElementById("users-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(usersUrl + "?name=" + encodeURIComponent(username), { 
      method: "DELETE", 
      headers: buildAuthHeaders({}) 
    });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadUsers();
  } catch (e) {
    if (msg) msg.textContent = "删除失败: " + (e.message || e);
  }
}

// ===== 代理 =====
// 初始化代理Modals
function initProxyModals() {
  var addModal = document.querySelector('#proxy-add-modal');
  var editModal = document.querySelector('#proxy-edit-modal');
  if (addModal) {
    addModal.querySelectorAll('[data-modal-close]').forEach(function(btn) {
      btn.addEventListener('click', function() { addModal.classList.remove('is-visible'); });
    });
  }
  if (editModal) {
    editModal.querySelectorAll('[data-modal-close]').forEach(function(btn) {
      btn.addEventListener('click', function() { editModal.classList.remove('is-visible'); });
    });
  }
}

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
      tr.innerHTML = "<td>" + name + "</td><td>" + urls.join(", ") + "</td>" +
        "<td><button class='bx--btn bx--btn--sm bx--btn--ghost' onclick='openEditProxyModal(\"" + name.replace(/"/g, '&quot;') + "\")'>编辑</button> " +
        "<button class='bx--btn bx--btn--sm bx--btn--danger--ghost' onclick='deleteProxy(\"" + name.replace(/"/g, '&quot;') + "\")'>删除</button></td>";
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "代理列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}

function openAddProxyModal() {
  document.getElementById("add-proxy-name").value = "";
  document.getElementById("add-proxy-urls").value = "";
  var modal = document.querySelector('#proxy-add-modal');
  if (modal) modal.classList.add('is-visible');
}

async function openEditProxyModal(name) {
  try {
    var res = await fetch(proxiesUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var p = data[name] || {};
    document.getElementById("edit-proxy-original-name").value = name;
    document.getElementById("edit-proxy-name").value = name;
    document.getElementById("edit-proxy-urls").value = (p.urls || []).join("\n");
    var modal = document.querySelector('#proxy-edit-modal');
    if (modal) modal.classList.add('is-visible');
  } catch (e) {
    var msg = document.getElementById("proxies-msg");
    if (msg) msg.textContent = "加载代理失败: " + (e.message || e);
  }
}

async function confirmAddProxy() {
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("add-proxy-name").value.trim();
  var raw = document.getElementById("add-proxy-urls").value.trim();
  if (!name) { if (msg) msg.textContent = "代理名必填"; return; }
  var urls = raw ? raw.split(/\n|,/).map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(proxiesUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, proxy: { urls: urls } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "新增成功";
    var modal = document.querySelector('#proxy-add-modal');
    if (modal) modal.classList.remove('is-visible');
    loadProxies();
  } catch (e) {
    if (msg) msg.textContent = "新增失败: " + (e.message || e);
  }
}

async function confirmEditProxy() {
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("edit-proxy-name").value.trim();
  var raw = document.getElementById("edit-proxy-urls").value.trim();
  if (!name) { if (msg) msg.textContent = "代理名必填"; return; }
  var urls = raw ? raw.split(/\n|,/).map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(proxiesUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, proxy: { urls: urls } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "更新成功";
    var modal = document.querySelector('#proxy-edit-modal');
    if (modal) modal.classList.remove('is-visible');
    loadProxies();
  } catch (e) {
    if (msg) msg.textContent = "更新失败: " + (e.message || e);
  }
}

async function deleteProxy(name) {
  if (!confirm("确定要删除代理 '" + name + "' 吗?")) return;
  var msg = document.getElementById("proxies-msg");
  if (msg) msg.textContent = "";
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
// 初始化隧道Modals
function initTunnelModals() {
  var addModal = document.querySelector('#tunnel-add-modal');
  var editModal = document.querySelector('#tunnel-edit-modal');
  if (addModal) {
    addModal.querySelectorAll('[data-modal-close]').forEach(function(btn) {
      btn.addEventListener('click', function() { addModal.classList.remove('is-visible'); });
    });
  }
  if (editModal) {
    editModal.querySelectorAll('[data-modal-close]').forEach(function(btn) {
      btn.addEventListener('click', function() { editModal.classList.remove('is-visible'); });
    });
  }
}
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
      tr.innerHTML = "<td>" + name + "</td><td>" + (t.password ? "******" : "") + "</td><td>" + servers.join(",") + "</td>" +
        "<td><button class='bx--btn bx--btn--sm bx--btn--ghost' onclick='openEditTunnelModal(\"" + name.replace(/"/g, '&quot;') +  "\")'>编辑</button> " +
        "<button class='bx--btn bx--btn--sm bx--btn--danger--ghost' onclick='deleteTunnel(\"" + name.replace(/"/g, '&quot;') + "\")'>删除</button></td>";
      tr.style.cursor = "pointer";
      tr.addEventListener("click", function(e) {
        if (e.target.tagName === "BUTTON") return;
        loadTunnelEndpoints(name);
      });
      if (tbody) tbody.appendChild(tr);
    });
    if (msg) msg.textContent = "隧道列表已加载";
  } catch (e) {
    if (msg) msg.textContent = "加载失败: " + (e.message || e);
  }
}

function openAddTunnelModal() {
  document.getElementById("add-tunnel-name").value = "";
  document.getElementById("add-tunnel-password").value = "";
  document.getElementById("add-tunnel-servers").value = "";
  var modal = document.querySelector('#tunnel-add-modal');
  if (modal) modal.classList.add('is-visible');
}

async function openEditTunnelModal(name) {
  try {
    var res = await fetch(tunnelsUrl, { headers: buildAuthHeaders({}) });
    if (!res.ok) throw new Error(await res.text());
    var data = await res.json();
    var t = data[name] || {};
    document.getElementById("edit-tunnel-original-name").value = name;
    document.getElementById("edit-tunnel-name").value = name;
    document.getElementById("edit-tunnel-password").value = "";
    document.getElementById("edit-tunnel-servers").value = (t.servers || []).join(",");
    var modal = document.querySelector('#tunnel-edit-modal');
    if (modal) modal.classList.add('is-visible');
  } catch (e) {
    var msg = document.getElementById("tunnels-msg");
    if (msg) msg.textContent = "加载隧道失败: " + (e.message || e);
  }
}

async function confirmAddTunnel() {
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("add-tunnel-name").value.trim();
  var password = document.getElementById("add-tunnel-password").value.trim();
  var serversRaw = document.getElementById("add-tunnel-servers").value.trim();
  if (!name) { if (msg) msg.textContent = "隧道名必填"; return; }
  var servers = serversRaw ? serversRaw.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(tunnelsUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, tunnel: { password: password || undefined, servers: servers } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "新增成功";
    var modal = document.querySelector('#tunnel-add-modal');
    if (modal) modal.classList.remove('is-visible');
    loadTunnels();
  } catch (e) {
    if (msg) msg.textContent = "新增失败: " + (e.message || e);
  }
}

async function confirmEditTunnel() {
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
  var name = document.getElementById("edit-tunnel-name").value.trim();
  var password = document.getElementById("edit-tunnel-password").value.trim();
  var serversRaw = document.getElementById("edit-tunnel-servers").value.trim();
  if (!name) { if (msg) msg.textContent = "隧道名必填"; return; }
  var servers = serversRaw ? serversRaw.split(",").map(function(s){return s.trim();}).filter(function(s){return s;}) : [];
  try {
    var res = await fetch(tunnelsUrl, { method: "POST", headers: buildAuthHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ name: name, tunnel: { password: password && password.length > 0 ? password : undefined, servers: servers } }) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "更新成功";
    var modal = document.querySelector('#tunnel-edit-modal');
    if (modal) modal.classList.remove('is-visible');
    loadTunnels();
  } catch (e) {
    if (msg) msg.textContent = "更新失败: " + (e.message || e);
  }
}

async function deleteTunnel(name) {
  if (!confirm("确定要删除隧道 '" + name + "' 吗?")) return;
  var msg = document.getElementById("tunnels-msg");
  if (msg) msg.textContent = "";
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
// 初始化服务Modals (简化版-保留原有内联表单)
function initServerModals() {
  // Server模块保留内联表单,暂不实现Modal
}

// ===== 规则 =====
// 初始化规则Modals (简化版-保留原有内联表单)
function initRuleModals() {
  // Rule模块保留内联表单,暂不实现Modal  
}

// ===== 防火墙 =====
// 初始化防火墙Modals (简化版-保留原有内联表单)
function initFirewallModals() {
  // Firewall模块保留内联表单,暂不实现Modal
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
        "<td>" + certStr + "</td>" +
        "<td>" + (s.firewall || "无") + "</td>" +
        "<td><button class='bx--btn bx--btn--sm bx--btn--ghost' onclick='openEditServerModal(\"" + name.replace(/"/g, '&quot;') + "\")'>编辑</button> " +
        "<button class='bx--btn bx--btn--sm bx--btn--danger--ghost' onclick='deleteServer(\"" + name.replace(/"/g, '&quot;') + "\")'>删除</button></td>";
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
    // 清空编辑区
    if (nameEl) nameEl.value = "";
    if (portEl) portEl.value = "";
    if (rawTCPEl) rawTCPEl.value = "";
    if (publicEl) publicEl.value = "";
    if (panelEl) panelEl.value = "";
    if (certEl) certEl.value = "";
    if (firewallEl) firewallEl.value = "";
    loadServers();
  } catch (e) {
    if (msg) msg.textContent = "保存失败: " + (e.message || e);
  }
}

function openEditServerModal(name) {
  fetch(serversUrl, { headers: buildAuthHeaders({}) })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var s = data[name] || {};
      document.getElementById("edit-server-original-name").value = name;
      document.getElementById("edit-server-name").value = name;
      document.getElementById("edit-server-port").value = (s.port != null ? s.port : "");
      var certStr = (typeof s.cert === "string" ? s.cert : "");
      document.getElementById("edit-server-cert").value = certStr;
      document.getElementById("edit-server-firewall").value = (s.firewall || "");
      var modal = document.querySelector('#server-edit-modal');
      if (modal) modal.classList.add('is-visible');
    })
    .catch(function(e) {
      var msg = document.getElementById("servers-msg");
      if (msg) msg.textContent = "加载服务失败: " + (e.message || e);
    });
}

async function deleteServer(name) {
  if (!confirm("确定要删除服务 '" + name + "' 吗?")) return;
  var msg = document.getElementById("servers-msg");
  if (msg) msg.textContent = "";
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
    // 清空编辑区
    if (edEl) edEl.value = "{}";
    if (idxEl) idxEl.value = "";
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
    // 清空编辑区
    if (nameEl) nameEl.value = "";
    if (allowEl) allowEl.value = "";
    if (blockEl) blockEl.value = "";
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

// Rule Modal helpers
function openEditRuleModal(idx) {
  document.getElementById("add-rule-editor").value = "{}";
  fetch(rulesUrl, { headers: buildAuthHeaders({}) })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var rule = (data || [])[idx];
      if (rule) {
        document.getElementById("add-rule-editor").value = JSON.stringify(rule, null, 2);
        document.getElementById("rule-index").value = idx;
      }
      var modal = document.querySelector('#rule-add-modal');
      if (modal) modal.classList.add('is-visible');
    })
    .catch(function(e) {
      var msg = document.getElementById("rules-msg");
      if (msg) msg.textContent = "加载规则失败: " + (e.message || e);
    });
}

async function deleteRule(idx) {
  if (!confirm("确定要删除规则 #" + idx + " 吗?")) return;
  var msg = document.getElementById("rules-msg");
  if (msg) msg.textContent = "";
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

// Firewall Modal helpers
function openEditFirewallModal(name) {
  document.getElementById("add-firewall-name").value = name;
  fetch(firewallsUrl, { headers: buildAuthHeaders({}) })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var fw = data[name] || {};
      document.getElementById("add-firewall-allow").value = (fw.allow || []).join("\n");
      document.getElementById("add-firewall-block").value = (fw.block || []).join("\n");
      var modal = document.querySelector('#firewall-add-modal');
      if (modal) modal.classList.add('is-visible');
    })
    .catch(function(e) {
      var msg = document.getElementById("firewalls-msg");
      if (msg) msg.textContent = "加载防火墙失败: " + (e.message || e);
    });
}

async function deleteFirewall(name) {
  if (!confirm("确定要删除防火墙策略 '" + name + "' 吗?")) return;
  var msg = document.getElementById("firewalls-msg");
  if (msg) msg.textContent = "";
  try {
    var res = await fetch(firewallsUrl + "?name=" + encodeURIComponent(name), { method: "DELETE", headers: buildAuthHeaders({}) });
    var text = await res.text();
    if (!res.ok) throw new Error(text);
    if (msg) msg.textContent = "删除成功";
    loadFirewalls();
    populateFirewallSelectors();
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

// Expose Modal functions to global scope for onclick handlers
window.openAddUserModal = openAddUserModal;
window.openEditUserModal = openEditUserModal;
window.deleteUser = deleteUser;
window.openAddProxyModal = openAddProxyModal;
window.openEditProxyModal = openEditProxyModal;
window.deleteProxy = deleteProxy;
window.openAddTunnelModal = openAddTunnelModal;
window.openEditTunnelModal = openEditTunnelModal;
window.deleteTunnel = deleteTunnel;
window.openEditServerModal = openEditServerModal;
window.deleteServer = deleteServer;
window.openEditRuleModal = openEditRuleModal;
window.deleteRule = deleteRule;
window.openEditFirewallModal = openEditFirewallModal;
window.openEditFirewallModal = openEditFirewallModal;
window.deleteFirewall = deleteFirewall;

// Also expose load functions
window.loadUsers = loadUsers;
window.loadProxies = loadProxies;
window.loadTunnels = loadTunnels;
window.loadServers = loadServers;
window.loadRules = loadRules;
window.loadFirewalls = loadFirewalls;
window.loadTunnelEndpoints = loadTunnelEndpoints;

// 绑定按钮事件
(function bindMgmtEvents(){
  function on(id, evt, fn){
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener(evt, fn);
      console.log("✓ Bound:", id);
    } else {
      console.warn("✗ Not found:", id);
    }
  }
  console.log("=== Starting button binding ===");
  on("btn-users-load", "click", loadUsers);
  on("btn-users-add", "click", openAddUserModal);
  on("confirm-add-user", "click", confirmAddUser);
  on("confirm-edit-user", "click", confirmEditUser);

  on("btn-proxies-load", "click", loadProxies);
  on("btn-proxies-add", "click", openAddProxyModal);
  on("confirm-add-proxy", "click", confirmAddProxy);
  on("confirm-edit-proxy", "click", confirmEditProxy);

  on("btn-tunnels-load", "click", loadTunnels);
  on("btn-tunnels-add", "click", openAddTunnelModal);
  on("confirm-add-tunnel", "click", confirmAddTunnel);
  on("confirm-edit-tunnel", "click", confirmEditTunnel);

  on("btn-servers-load", "click", loadServers);
  on("btn-servers-add", "click", function() {
    var modal = document.querySelector('#server-add-modal');
    if (modal) modal.classList.add('is-visible');
  });
  on("btn-servers-save", "click", saveServer);
  on("btn-servers-delete", "click", deleteSelectedServer);
  on("confirm-add-server", "click", saveServer);
  on("confirm-edit-server", "click", saveServer);

  on("btn-rules-load", "click", loadRules);
  on("btn-rules-add", "click", function() {
    var modal = document.querySelector('#rule-add-modal');
    if (modal) modal.classList.add('is-visible');
  });
  on("btn-rules-save", "click", saveRule);
  on("btn-rules-delete", "click", deleteSelectedRule);
  on("confirm-add-rule", "click", saveRule);
  on("confirm-edit-rule", "click", saveRule);

  on("btn-firewalls-load", "click", loadFirewalls);
  on("btn-firewalls-add", "click", function() {
    var modal = document.querySelector('#firewall-add-modal');
    if (modal) modal.classList.add('is-visible');
  });
  on("btn-firewalls-save", "click", saveFirewall);
  on("btn-firewalls-delete", "click", deleteSelectedFirewall);
  on("confirm-add-firewall", "click", saveFirewall);
  on("confirm-edit-firewall", "click", saveFirewall);
  
  // 初始加载一次
    refreshStats();
    // 填充防火墙下拉框
    populateFirewallSelectors();
    // 初始化Carbon组件
    setTimeout(function() {
      if (typeof CarbonComponents !== 'undefined') {
        if (CarbonComponents.Toggle && CarbonComponents.Toggle.init) {
          CarbonComponents.Toggle.init();
        }
        initUserModals();
        initProxyModals();
        initTunnelModals();
        initServerModals();
        initRuleModals();
        initFirewallModals();
      }
    }, 100);
  });
}); // End of DOMContentLoaded
`
