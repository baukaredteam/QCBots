// Shared safe API client (Stage F). No credentials in JS storage; cookies only.
// Same-origin by default: the shell is served by the API server, so /api/v1
// resolves to the host, port and scheme the page was loaded from. This keeps a
// custom port, HTTPS and a reverse proxy working without a hardcoded origin.
const API_BASE = '';
function getCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
function csrfHeaders() {
  const t = getCookie('csrf_token');
  return t ? { 'X-CSRF-Token': t } : {};
}
async function api(path, options) {
  options = options || {};
  const url = API_BASE + path;
  const headers = Object.assign({ 'Content-Type': 'application/json', 'Origin': window.location.origin }, options.headers || {});
  if (options.method && options.method !== 'GET' && options.method !== 'HEAD') {
    Object.assign(headers, csrfHeaders());
  }
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: headers,
    credentials: 'include',
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined
  });
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { window.location.href = 'login.html'; throw { status: 401, data: data }; }
  if (!res.ok) throw { status: res.status, data: data };
  return data;
}
// Multipart upload uses the same cookie + CSRF contract as api(), but must not
// set Content-Type: the browser adds the multipart boundary.
async function apiForm(path, formData) {
  const url = API_BASE + path;
  const headers = Object.assign({ 'Origin': window.location.origin }, csrfHeaders());
  const res = await fetch(url, { method: 'POST', headers: headers, credentials: 'include', body: formData });
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { window.location.href = 'login.html'; throw { status: 401, data: data }; }
  if (!res.ok) throw { status: res.status, data: data };
  return data;
}
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text != null) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function showError(containerId, msg) {
  const c = document.getElementById(containerId);
  if (c) c.textContent = msg;
}
