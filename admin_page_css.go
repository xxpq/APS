package main

var admin_page_css = `
:root {
  --bg: #f4f4f4;
}
body {
  font-family: "IBM Plex Sans", system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
  background: var(--bg);
  padding-top: 80px; /* Prevent header from overlapping content - increased for better clearance */
  margin: 0;
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
  margin: 1rem auto 0; /* Add top margin to prevent overlap with fixed header */
  padding: 48px;
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
    padding-top: 80px; /* Match desktop padding */
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
`
