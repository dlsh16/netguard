/* =====================================================
   NetGuard Dashboard ??SNMP ?ㅼ닔吏??곗씠?곕쭔 ?쒖떆
   하드코딩 샘플 데이터 없음
   ===================================================== */
'use strict';

// Auth guard (secondary check ??primary is in <head>)
if (!localStorage.getItem('ng_token')) { location.href = '/login'; }

// ===== Chart.js 鍮??곗씠???뚮윭洹몄씤 =====
const emptyChartPlugin = {
  id: 'emptyChart',
  afterDraw(chart) {
    const allEmpty = chart.data.datasets.every(d => !d.data || d.data.length === 0);
    if (!allEmpty) return;
    const { ctx, width, height } = chart;
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '12px sans-serif';
    ctx.fillStyle = '#4a5568';
    ctx.fillText('데이터 수집 대기중', width / 2, height / 2);
    ctx.restore();
  }
};
Chart.register(emptyChartPlugin);

// ===== STATE =====
let currentPage = 'dashboard';
let overviewMetric = 'cpu_pct';
let networkMetric = 'net_in_mb';
let overviewHours = 6;
let networkHours = 6;
let overviewRenderRun = 0;
let networkRenderRun = 0;
let selectedServerId = null;
let selectedSwitchId = null;
let chartInstances = {};
let editingDeviceId = null;
let alertConfigLoaded = false;
let ws = null;

const state = {
  devices: [],
  live:    {},    // live results indexed by name, ip:<address>, and id:<device_id>
  events:  [],
  cves:    { total: 0, counts: {}, items: [], _loaded: false },
  checkResults: { summary: {}, latest_runs: [], item_summary: [], server_summary: [], _loaded: false },
  summary: { devices: 0, active_events: 0, critical_events: 0 }
};

// ===== API =====
async function api(path, method = 'GET', body = null) {
  const token = localStorage.getItem('ng_token') || '';
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) {
    localStorage.removeItem('ng_token');
    localStorage.removeItem('ng_user');
    location.href = '/login';
    throw new Error('Session expired');
  }
  if (!r.ok) {
    let detail = '';
    try {
      const err = await r.json();
      detail = err.detail ? ` - ${err.detail}` : '';
    } catch (e) {}
    throw new Error(`${method} /api${path}: ${r.status}${detail}`);
  }
  return r.json();
}

async function fetchHistory(deviceId, metric, hours = 1) {
  try {
    return await api(`/metrics/${deviceId}?metric=${metric}&hours=${hours}`);
  } catch (e) {
    return [];
  }
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', async () => {
  initNavigation();
  ensureNetworkToggleControls();
  initOverviewControls();
  initUserUI();
  applyRolePermissions();
  updateClock();
  setInterval(updateClock, 1000);
  await Promise.all([loadAll(), loadCVEs(), loadCheckResults()]);
  await loadThresholds();
  connectWebSocket();
  renderPage(currentPage);
  setInterval(() => loadAll().then(() => renderPage(currentPage)), 60000);
});

async function loadAll() {
  try {
    const [devices, events, summary] = await Promise.all([
      api('/devices'),
      api('/events?hours=24&limit=100'),
      api('/dashboard/summary')
    ]);
    state.devices = devices;
    state.events  = (events || []).filter(e => !isSwitchPortErrorEvent(e));
    state.summary = summary;
    await loadLatestMetrics();
    updateBadges();
    updateAlertBanner();
  } catch (e) {
    console.error('Data load failed:', e);
  }
}

async function loadLatestMetrics() {
  try {
    const rows = await api('/metrics/latest');
    mergeLatestMetrics(rows || []);
  } catch (e) {
    console.error('Latest metrics load failed:', e);
  }
}

async function loadCVEs() {
  try {
    const data = await api('/security/cves');
    state.cves = { ...data, _loaded: true };
    updateBadges();
  } catch (e) {
    console.error('CVE load failed:', e);
    state.cves._loaded = true;
  }
}

async function loadCheckResults() {
  try {
    const data = await api('/security/checks/summary');
    state.checkResults = { ...data, _loaded: true };
    updateBadges();
  } catch (e) {
    console.error('Check result load failed:', e);
    state.checkResults._loaded = true;
  }
}

function ensureNetworkToggleControls() {
  const ctx = document.getElementById('chart-network');
  const card = ctx?.closest('.chart-card');
  const header = card?.querySelector('.card-header');
  if (!header || document.getElementById('network-in-btn')) return;

  const title = header.querySelector('.card-title');
  if (title) title.textContent = '네트워크 트래픽';

  const actions = document.createElement('div');
  actions.className = 'card-actions';
  actions.innerHTML = `
    <div class="metric-toggle" aria-label="네트워크 데이터 선택">
      <button type="button" class="metric-toggle-btn active" id="network-in-btn" onclick="setNetworkMetric('net_in_mb')">수신</button>
      <button type="button" class="metric-toggle-btn" id="network-out-btn" onclick="setNetworkMetric('net_out_mb')">송신</button>
    </div>`;
  const range = document.createElement('select');
  range.className = 'select-sm';
  range.id = 'network-range-select';
  range.setAttribute('onchange', 'setNetworkTimeRange(this.value)');
  range.innerHTML = '<option value="1h">1시간</option><option value="6h" selected>6시간</option><option value="24h">24시간</option><option value="7d">7일</option>';
  actions.appendChild(range);
  header.appendChild(actions);
}

function refreshData() { loadAll().then(() => renderPage(currentPage)); }

// ===== WEBSOCKET =====
function connectWebSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'metrics') {
      (msg.devices || []).forEach(indexLiveResult);
      if (msg.environment) state.live['__env__'] = msg.environment;
      renderPage(currentPage);
      updateBadges();
    } else if (msg.type === 'alert') {
      const alerts = (msg.alerts || []).map(normalizeEvent).filter(e => !isSwitchPortErrorEvent(e));
      if (alerts.length === 0) return;
      state.events.unshift(...alerts);
      updateBadges();
      updateAlertBanner();
      // 알림 패널이 열려 있으면 실시간 갱신
      if (document.getElementById('alert-panel')?.classList.contains('open')) {
        renderAlertPanel();
      }
    } else if (msg.type === 'events_resolved') {
      const resolvedIds = new Set(msg.event_ids || []);
      state.events.forEach(e => {
        if (resolvedIds.has(e.id)) e.status = 'resolved';
      });
      updateBadges();
      updateAlertBanner();
      renderPage(currentPage);
      if (document.getElementById('alert-panel')?.classList.contains('open')) {
        renderAlertPanel();
      }
    }
  };

  ws.onclose = () => setTimeout(connectWebSocket, 5000);
  setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
  }, 30000);
}

function normalizeEvent(e) {
  return {
    id:          e.id,
    time:        e.time || e.timestamp || new Date().toISOString(),
    device_name: e.device_name || e.device || '--',
    severity:    e.severity,
    category:    e.category,
    message:     e.message,
    status:      e.status || 'active'
  };
}

function isSwitchPortErrorEvent(event) {
  const message = String(event?.message || '');
  return /포트 .*에러 급증/.test(message) ||
    /in:\d+.*out:\d+/.test(message) ||
    /\?ы듃 .*\?먮윭/.test(message);
}

// ===== DEVICE HELPERS =====
function indexLiveResult(result) {
  if (!result) return;
  if (result.device) state.live[result.device] = result;
  if (result.ip) state.live[`ip:${result.ip}`] = result;
  if (result.device_id !== undefined && result.device_id !== null) {
    state.live[`id:${result.device_id}`] = result;
  }
}

function mergeLatestMetrics(rows) {
  const grouped = {};
  rows.forEach(r => {
    const id = r.device_id;
    if (id === undefined || id === null) return;
    const device = state.devices.find(d => Number(d.id) === Number(id));
    const live = grouped[id] || state.live[`id:${id}`] || {
      device_id: id,
      device: device?.name || r.device_name,
      ip: device?.ip_address,
      type: device?.type || 'server',
      status: 'online',
      metrics: {}
    };
    live.device = device?.name || live.device || r.device_name;
    live.ip = device?.ip_address || live.ip;
    live.type = device?.type || live.type || 'server';
    live.status = 'online';
    live.timestamp = r.time || live.timestamp;
    live.metrics = live.metrics || {};
    live.metrics[r.metric_name] = Number(r.value);
    grouped[id] = live;
  });
  Object.values(grouped).forEach(indexLiveResult);
}

function getLive(deviceOrName) {
  if (!deviceOrName) return null;
  if (typeof deviceOrName === 'object') {
    return state.live[`id:${deviceOrName.id}`] ||
      state.live[`ip:${deviceOrName.ip_address}`] ||
      state.live[deviceOrName.name] ||
      null;
  }
  return state.live[deviceOrName] || null;
}

function getMetric(deviceName, key, fallback = null) {
  const v = getLive(deviceName)?.metrics?.[key];
  return (v !== undefined && v !== null) ? v : fallback;
}

function getEnvironmentLive(envDev) {
  const deviceLive = envDev ? getLive(envDev) : null;
  const deviceMetrics = deviceLive?.metrics || null;
  if (deviceMetrics?.temp_c != null || deviceMetrics?.humidity_pct != null) {
    return deviceLive;
  }
  const globalEnv = state.live['__env__'];
  if (globalEnv?.temp_c != null || globalEnv?.humidity_pct != null) {
    return { metrics: globalEnv };
  }
  return deviceLive || (globalEnv ? { metrics: globalEnv } : null);
}

function isWindowsServer(device) {
  const os = `${device.os_version || ''} ${device.name || ''}`.toLowerCase();
  return os.includes('windows') || os.includes('win32') || os.includes('win64');
}

function isServerDevice(device) {
  const type = String(device?.type || '').toLowerCase();
  const snmpVersion = String(device?.snmp_version || '').toLowerCase();
  return type === 'server' || type === 'agent' || snmpVersion === 'agent';
}

function isEnvironmentDevice(device) {
  const type = String(device?.type || '').toLowerCase();
  const text = `${device?.name || ''} ${device?.os_version || ''}`.toLowerCase();
  return ['env', 'rpi', 'environment', 'sensor'].includes(type) ||
    text.includes('항온') ||
    text.includes('습도') ||
    text.includes('온도') ||
    text.includes('temperature') ||
    text.includes('humidity');
}

function isUtilityDevice(device) {
  const type = String(device?.type || '').toLowerCase();
  return type === 'ups' || isEnvironmentDevice(device);
}

function deviceGroupKey(device) {
  if (String(device?.type || '').toLowerCase() === 'switch') return 'switch';
  if (isServerDevice(device)) return 'server';
  if (isUtilityDevice(device)) return 'utility';
  return 'utility';
}

function fmtGb(value) {
  return value === undefined || value === null ? '--' : `${Number(value).toFixed(1)} GB`;
}

function fmtChartTime(ts) {
  if (!ts) return '';
  const normalized = String(ts).replace(' ', 'T');
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return String(ts).slice(11, 16);
  return d.toLocaleTimeString('ko-KR', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
}

function networkBucketMinutes(hours) {
  if (hours <= 1) return 5;
  if (hours <= 6) return 15;
  if (hours <= 24) return 60;
  return 360;
}

function floorToBucketMs(value, bucketMinutes) {
  const bucketMs = bucketMinutes * 60 * 1000;
  return Math.floor(value / bucketMs) * bucketMs;
}

function buildNetworkTimeline(hours) {
  const bucketMinutes = networkBucketMinutes(hours);
  const endMs = floorToBucketMs(Date.now(), bucketMinutes);
  const startMs = endMs - (hours * 60 * 60 * 1000);
  const stepMs = bucketMinutes * 60 * 1000;
  const points = [];
  for (let ts = startMs; ts <= endMs; ts += stepMs) points.push(ts);
  return { bucketMinutes, points };
}

function fmtNetworkChartTime(ms, hours) {
  const d = new Date(ms);
  if (hours <= 6) {
    return d.toLocaleTimeString('ko-KR', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  }
  return d.toLocaleString('ko-KR', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
}

function bucketNetworkRows(rows, bucketMinutes) {
  const buckets = new Map();
  rows.forEach(row => {
    if (!row?.time) return;
    const rawMs = new Date(String(row.time).replace(' ', 'T')).getTime();
    if (Number.isNaN(rawMs)) return;
    const bucketMs = floorToBucketMs(rawMs, bucketMinutes);
    const current = buckets.get(bucketMs) || { sum: 0, count: 0 };
    current.sum += Number(row.avg || 0);
    current.count += 1;
    buckets.set(bucketMs, current);
  });
  return new Map(Array.from(buckets.entries()).map(([key, value]) => [
    key,
    value.count ? Number((value.sum / value.count).toFixed(2)) : null
  ]));
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));
}

function portDisplayName(port) {
  return String(port?.if_name || port?.name || port?.descr || `if${port?.index ?? ''}`).trim();
}

function portShortLabel(port) {
  const raw = portDisplayName(port);
  const slashMatch = raw.match(/(\d+(?:\/\d+)+)$/);
  if (slashMatch) return slashMatch[1].split('/').pop();
  const numMatch = raw.match(/(\d+)$/);
  return numMatch ? numMatch[1] : String(port?.index ?? raw);
}

function portSearchText(port) {
  return [
    port?.if_name,
    port?.name,
    port?.descr,
    port?.alias
  ].filter(Boolean).join(' ').toLowerCase();
}

function isVirtualSwitchPort(port) {
  return /(vlan|vlan-interface|null|loopback)/i.test(portSearchText(port));
}

function physicalPortNumber(port) {
  const raw = portDisplayName(port);
  const slashMatch = raw.match(/(\d+(?:\/\d+)+)$/);
  if (slashMatch) return Number(slashMatch[1].split('/').pop());
  const numMatch = raw.match(/(\d+)$/);
  if (numMatch) return Number(numMatch[1]);
  return Number(port?.index || 0);
}

function sortSwitchPorts(ports) {
  return [...ports].sort((a, b) => {
    const ag = isVirtualSwitchPort(a) ? 1 : 0;
    const bg = isVirtualSwitchPort(b) ? 1 : 0;
    if (ag !== bg) return ag - bg;
    const av = physicalPortNumber(a);
    const bv = physicalPortNumber(b);
    if (av !== bv) return av - bv;
    return Number(a?.index || 0) - Number(b?.index || 0);
  });
}

function diskUsageBadge(pct) {
  if (pct >= 90) return 'critical';
  if (pct >= 80) return 'medium';
  return 'ok';
}

function renderDiskRows(device, disks) {
  if (!disks || disks.length === 0) {
    const msg = device.snmp_version === 'agent'
      ? '디스크 파티션 데이터 없음 (에이전트 수집 대기중)'
      : '디스크 파티션 데이터 없음 (hrStorage 미응답)';
    return `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">${msg}</td></tr>`;
  }
  const kind = isWindowsServer(device) ? '디스크' : '파티션';
  return disks.map(d => {
    const pct = Number(d.used_pct || 0);
    return `<tr>
      <td>${kind}</td>
      <td style="font-family:var(--mono)">${d.path || '--'}</td>
      <td>${fmtGb(d.size_gb)}</td>
      <td>${fmtGb(d.used_gb)}</td>
      <td>${fmtGb(d.free_gb)}</td>
      <td><span class="badge ${diskUsageBadge(pct)}">${pct.toFixed(1)}%</span></td>
    </tr>`;
  }).join('');
}

function focusDiskDetail() {
  const el = document.getElementById('disk-detail-section');
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  el.classList.add('highlight-once');
  setTimeout(() => el.classList.remove('highlight-once'), 1200);
}

function deviceStatus(device) {
  const live = getLive(device);
  if (!live) return 'unknown';
  if (live.status === 'offline') return 'offline';
  const m = live.metrics || {};
  switch (device.type) {
    case 'server': {
      const maxDisk = m.disks ? Math.max(...m.disks.map(d => d.used_pct), 0) : 0;
      if ((m.cpu_pct || 0) > 90 || (m.mem_pct || 0) > 85 || maxDisk > 90) return 'critical';
      if ((m.cpu_pct || 0) > 75 || (m.mem_pct || 0) > 75 || maxDisk > 80) return 'warning';
      return 'normal';
    }
    case 'switch': {
      const hasActiveAlert = state.events.some(e =>
        e.status === 'active' && e.device_name === device.name && !isSwitchPortErrorEvent(e)
      );
      return hasActiveAlert ? 'warning' : 'normal';
    }
    case 'ups':
      if ((m.battery_pct ?? 100) < 15) return 'critical';
      if ((m.battery_pct ?? 100) < 30) return 'warning';
      return 'normal';
    case 'env': case 'rpi': case 'environment': case 'sensor':
      if ((m.temp_c || 0) > 32) return 'critical';
      if ((m.temp_c || 0) > 27) return 'warning';
      return 'normal';
    default: return 'normal';
  }
}

function statusLabel(s) {
  return { critical:'위험', warning:'경고', normal:'정상', offline:'오프라인', unknown:'미확인' }[s] || s;
}
function statusColor(s) {
  return { critical:'#ef4444', warning:'#f59e0b', normal:'#22c55e', offline:'#6b7280', unknown:'#6b7280' }[s] || '#6b7280';
}
function badgeCls(s) {
  return { critical:'critical', warning:'medium', normal:'ok', offline:'info', unknown:'info' }[s] || 'info';
}
const TYPE_KO = { server:'서버', agent:'서버', switch:'스위치', env:'항온항습기', environment:'항온항습기', sensor:'센서', ups:'UPS', rpi:'라즈베리파이' };

// ===== NAVIGATION =====
function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(item =>
    item.addEventListener('click', () => navigateTo(item.dataset.page))
  );
}

function initOverviewControls() {
  document.getElementById('overview-cpu-btn')?.addEventListener('click', () => setOverviewMetric('cpu_pct'));
  document.getElementById('overview-mem-btn')?.addEventListener('click', () => setOverviewMetric('mem_pct'));
  document.getElementById('network-in-btn')?.addEventListener('click', () => setNetworkMetric('net_in_mb'));
  document.getElementById('network-out-btn')?.addEventListener('click', () => setNetworkMetric('net_out_mb'));
}

function navigateTo(page) {
  if (page === 'devices' && !isAdminUser()) {
    page = 'dashboard';
  }
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');
  document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
  const pageEl = document.getElementById(`page-${page}`);
  if (pageEl) pageEl.classList.add('active');
  const titles = {
    dashboard:'전체 대시보드', servers:'서버 모니터링', switches:'스위치 모니터링',
    environment:'항온항습 / UPS', processes:'프로세스 모니터링',
    security:'취약점 (CVE/CWE/CVSS)', 'security-checks':'점검 결과 저장', events:'이벤트 로그',
    thresholds:'임계값 설정', alerts:'알림 설정', devices:'장비 관리',
    users:'사용자 관리', changelog:'업데이트 내역'
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  currentPage = page;
  renderPage(page);
}

function renderPage(page) {
  const fn = {
    dashboard:   renderDashboard,   servers:     renderServers,
    switches:    renderSwitches,    environment: renderEnvironment,
    processes:   renderProcesses,   security:    renderSecurity,
    'security-checks': renderSecurityChecks,
    events:      renderEvents,      devices:     renderDevices,
    alerts:      renderAlertConfig, users:       renderUsers,
    changelog:   renderChangelog
  }[page];
  if (fn) fn().catch(e => console.error(`renderPage(${page}):`, e));
}

// ===== SIDEBAR =====
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
}

// ===== BADGES =====
function updateBadges() {
  const active = state.events.filter(e => e.status === 'active' && !isSwitchPortErrorEvent(e));
  const srvEvt = active.filter(e => state.devices.find(d => d.name === e.device_name && d.type === 'server'));
  const swEvt  = active.filter(e => state.devices.find(d => d.name === e.device_name && d.type === 'switch'));
  setBadge('badge-dashboard', active.length);
  setBadge('badge-servers',   srvEvt.length);
  setBadge('badge-switches',  swEvt.length);
  setBadge('badge-security',  state.cves.total || 0);
  setBadge('badge-security-checks', state.checkResults?.summary?.fail_count || 0);
  setBadge('badge-events', active.length);
  const bellEl = document.getElementById('bell-badge-count');
  if (bellEl) {
    bellEl.textContent = active.length;
    bellEl.style.display = active.length > 0 ? '' : 'none';
  }
  // 알림 패널이 열려 있으면 카운트도 갱신
  const apBadge = document.getElementById('ap-badge-count');
  if (apBadge) {
    apBadge.textContent = active.length;
    apBadge.className = 'ap-count' + (active.length === 0 ? ' zero' : '');
  }
}

function setBadge(id, count) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = count;
  el.style.display = count > 0 ? '' : 'none';
}

function updateAlertBanner() {
  const banner = document.getElementById('alert-banner');
  if (!banner) return;
  const crits = state.events.filter(e => e.status === 'active' && e.severity === 'critical');
  if (crits.length > 0) {
    banner.style.display = '';
    const msgEl = document.getElementById('alert-banner-msg');
    if (msgEl) msgEl.textContent = `긴급 ${crits.length}건: ${crits[0]?.message || ''}`;
  } else {
    banner.style.display = 'none';
  }
}

// ===== CLOCK =====
function updateClock() {
  const el = document.getElementById('last-update');
  if (el) el.textContent = '마지막 갱신: ' + new Date().toLocaleTimeString('ko-KR');
}

// ===== DASHBOARD =====
async function renderDashboard() {
  renderSummaryCards();
  renderDeviceGrid();
  renderEventList();
  await renderOverviewChart();
  await renderNetworkChart();
}

function renderSummaryCards() {
  // Servers
  const servers = state.devices.filter(d => d.type === 'server');
  const srvNormal = servers.filter(d => ['normal','unknown'].includes(deviceStatus(d))).length;
  const srvBad    = servers.filter(d => ['critical','warning'].includes(deviceStatus(d))).length;
  setEl('summary-srv-count', servers.length > 0 ? servers.length : '--');
  if (servers.length === 0) {
    setElHtml('summary-srv-status', '<span style="color:var(--text-muted)">장비 미등록</span>');
  } else {
    setElHtml('summary-srv-status',
      `<span class="dot green"></span>${srvNormal} 정상${srvBad > 0 ? ` <span class="dot red"></span>${srvBad} 경보` : ''}`);
  }

  // Switches
  const switches = state.devices.filter(d => d.type === 'switch');
  const swNormal = switches.filter(d => ['normal','unknown'].includes(deviceStatus(d))).length;
  const swBad    = switches.filter(d => ['critical','warning'].includes(deviceStatus(d))).length;
  setEl('summary-sw-count', switches.length > 0 ? switches.length : '--');
  if (switches.length === 0) {
    setElHtml('summary-sw-status', '<span style="color:var(--text-muted)">장비 미등록</span>');
  } else {
    setElHtml('summary-sw-status',
      `<span class="dot green"></span>${swNormal} 정상${swBad > 0 ? ` <span class="dot red"></span>${swBad} 경보` : ''}`);
  }

  // Environment
  const envDev  = state.devices.find(isEnvironmentDevice);
  const envLive = getEnvironmentLive(envDev);
  const envM    = envLive?.metrics;
  if (envM?.temp_c != null) {
    setEl('summary-env-val', envM.temp_c.toFixed(1) + '°C');
    const tempWarn = envM.temp_c > 27;
    const humiWarn = (envM.humidity_pct || 0) > 60;
    const envOk = !tempWarn && !humiWarn;
    const envLabel = tempWarn ? '온도 경고' : humiWarn ? '습도 경고' : '정상';
    setElHtml('summary-env-status',
      `<span class="dot ${envOk ? 'green' : 'red'}"></span>${envLabel} | 습도 ${(envM.humidity_pct||0).toFixed(0)}%`);
  } else {
    setEl('summary-env-val', '--');
    setElHtml('summary-env-status',
      envDev ? '<span style="color:var(--text-muted)">수집 대기중</span>' : '<span style="color:var(--text-muted)">장비 미등록</span>');
  }

  // UPS
  const upsDev = state.devices.find(d => d.type === 'ups');
  const upsM   = upsDev ? getLive(upsDev)?.metrics : null;
  if (upsM?.battery_pct != null) {
    setEl('summary-ups-val', upsM.battery_pct.toFixed(0) + '%');
    const battOk = (upsM.battery_pct ?? 100) >= 30;
    const runtimeText = upsM.runtime_min != null
      ? ` | 예상 대기 시간 ${(upsM.runtime_min || 0).toFixed(0)}분`
      : '';
    setElHtml('summary-ups-status',
      `<span class="dot ${battOk ? 'green' : 'red'}"></span>${battOk ? '정상' : '경고'} | 입력 ${(upsM.input_v||0).toFixed(0)}V${runtimeText}`);
  } else {
    setEl('summary-ups-val', '--');
    setElHtml('summary-ups-status',
      upsDev ? '<span style="color:var(--text-muted)">수집 대기중</span>' : '<span style="color:var(--text-muted)">장비 미등록</span>');
  }

  // CVE
  const cveEl = document.getElementById('summary-cve-val');
  if (cveEl) {
    if (!state.cves._loaded) {
      cveEl.textContent = '--';
      cveEl.className = 'summary-value';
      setElHtml('summary-cve-status', '<span style="color:var(--text-muted)">로딩중</span>');
    } else {
      const total  = state.cves.total || 0;
      const counts = state.cves.counts || {};
      cveEl.textContent = total;
      cveEl.className   = 'summary-value' + (total > 0 ? ' critical' : '');
      setElHtml('summary-cve-status',
        total === 0
          ? '<span class="dot green"></span>취약점 없음'
          : `<span class="dot red"></span>Critical ${counts.CRITICAL||0} <span class="dot orange"></span>High ${counts.HIGH||0}`);
    }
  }
}

function renderDeviceGrid() {
  const grid = document.getElementById('device-grid');
  if (!grid) return;
  if (state.devices.length === 0) {
    grid.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:16px;grid-column:1/-1">등록된 장비가 없습니다.</div>';
    return;
  }
  const pageMap = { server:'servers', switch:'switches', env:'environment', ups:'environment', rpi:'environment', environment:'environment', sensor:'environment', agent:'servers' };
  const groups = [
    ['switch', 'Switch', state.devices.filter(d => deviceGroupKey(d) === 'switch')],
    ['server', 'Server', state.devices.filter(d => deviceGroupKey(d) === 'server')],
    ['utility', 'Utility', state.devices.filter(d => deviceGroupKey(d) === 'utility')],
  ];
  grid.innerHTML = groups.map(([key, label, devices]) => {
    if (!devices.length) return '';
    const cards = devices.map(d => {
      const status = deviceStatus(d);
      const m = getLive(d)?.metrics;
      let metric;
      if (!m) {
        metric = '<span style="color:var(--text-muted)">대기중</span>';
      } else {
        switch (d.type) {
          case 'server':
          case 'agent':
            metric = `CPU ${(m.cpu_pct||0).toFixed(0)}%`;
            break;
          case 'switch':
            metric = `${(m.interfaces||[]).filter(i=>i.status==='up').length}/${(m.interfaces||[]).length} 포트`;
            break;
          case 'ups':
            metric = `배터리 ${(m.battery_pct??0).toFixed(0)}%`;
            break;
          case 'env':
          case 'rpi':
          case 'environment':
          case 'sensor':
            metric = `${(m.temp_c||0).toFixed(1)}°C`;
            break;
          default:
            metric = '수집중';
        }
      }
      return `<div class="device-cell status-${status}" onclick="navigateTo('${pageMap[d.type]||'dashboard'}')">
        <div class="device-name" title="${escapeHtml(d.name)}">${escapeHtml(d.name)}</div>
        <div class="device-type-label">${TYPE_KO[d.type]||d.type}</div>
        <div class="device-metric" style="color:${statusColor(status)}">${metric}</div>
      </div>`;
    }).join('');
    return `<div class="device-group device-group-${key}">
      <div class="device-group-title">${label}<span>${devices.length}</span></div>
      <div class="device-group-grid">${cards}</div>
    </div>`;
  }).join('');
}
function renderEventList() {
  const el = document.getElementById('event-list');
  if (!el) return;
  const recent = state.events.filter(e => !isSwitchPortErrorEvent(e)).slice(0, 6);
  if (recent.length === 0) {
    el.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:12px">최근 이벤트 없음</div>';
    return;
  }
  el.innerHTML = recent.map(e => `
    <div class="event-item">
      <span class="event-sev ${e.severity}">${e.severity.toUpperCase()}</span>
      <div class="event-body">
        <div class="event-title">${escapeHtml(e.message)}</div>
        <div class="event-meta">${escapeHtml(e.device_name||'')} · ${escapeHtml(e.category||'')}</div>
      </div>
      <div class="event-time">${fmtTime(e.time)}</div>
    </div>`).join('');
}

async function renderOverviewChart() {
  const ctx = document.getElementById('chart-overview');
  if (!ctx) return;
  const runId = ++overviewRenderRun;
  const servers = state.devices.filter(isServerDevice);
  const metricKey = overviewMetric === 'mem_pct' ? 'mem_pct' : 'cpu_pct';
  const metricTitle = metricKey === 'mem_pct' ? 'Memory' : 'CPU';
  const empty = () => {
    if (runId !== overviewRenderRun) return;
    destroyChart('overview');
    chartInstances['overview'] = makeEmptyChart(ctx, `${metricTitle} %`, 0, 100);
  };
  if (servers.length === 0) {
    empty();
    return;
  }

  const series = await Promise.all(servers.map(async s => {
    const history = await fetchHistory(s.id, metricKey, overviewHours);
    const live = getLive(s)?.metrics || {};
    const now = new Date().toISOString();
    return {
      server: s,
      rows: history.length ? history : (live[metricKey] != null ? [{ time: now, avg: Number(live[metricKey]) }] : [])
    };
  }));

  const timeMap = new Map();
  series.forEach(item => {
    item.rows.forEach(p => {
      if (p?.time) timeMap.set(String(p.time), fmtChartTime(p.time));
    });
  });
  const timeSortValue = t => {
    const parsed = new Date(String(t).replace(' ', 'T')).getTime();
    return Number.isNaN(parsed) ? 0 : parsed;
  };
  const timeKeys = Array.from(timeMap.keys()).sort((a, b) => timeSortValue(a) - timeSortValue(b));
  if (timeKeys.length === 0) {
    empty();
    return;
  }
  const labels = timeKeys.map(t => timeMap.get(t));
  const colors = ['#3B82F6','#22c55e','#f59e0b','#ef4444','#a855f7','#06b6d4','#84cc16','#f97316'];
  const toValueMap = rows => new Map(rows.map(p => [String(p.time), Number(p.avg)]));
  const datasets = series
    .map((item, i) => {
      if (item.rows.length === 0) return null;
      const color = colors[i % colors.length];
      const values = toValueMap(item.rows);
      return {
        label: `${item.server.name} ${metricTitle}`,
        data: timeKeys.map(t => values.has(t) ? values.get(t) : null),
        borderColor: color,
        backgroundColor: 'transparent',
        borderWidth: 1.7,
        pointRadius: timeKeys.length === 1 ? 3 : 0,
        tension: 0.35,
        spanGaps: true
      };
    })
    .filter(Boolean);
  if (datasets.length === 0) {
    empty();
    return;
  }
  if (runId !== overviewRenderRun) return;
  destroyChart('overview');
  chartInstances['overview'] = new Chart(ctx, {
    type: 'line', data: { labels, datasets }, options: chartOptions(`${metricTitle} %`, 0, 100)
  });
}

async function renderNetworkChartLegacy() {
  const ctx = document.getElementById('chart-network');
  if (!ctx) return;
  destroyChart('network');
  // 누적 카운터(octets) 기반 현재 포트별 합계 표시
  const swDevices = state.devices.filter(d => d.type === 'switch');
  const allIfaces = [];
  swDevices.forEach(d => (getLive(d)?.metrics?.interfaces || []).filter(i => i.status === 'up').forEach(i => {
    allIfaces.push({ name: `${d.name}:${i.name}`, inMB: i.in_octets/1024/1024, outMB: i.out_octets/1024/1024 });
  }));
  if (allIfaces.length === 0) {
    chartInstances['network'] = makeEmptyChart(ctx, 'MB', 0, 100);
    return;
  }
  const top = allIfaces.sort((a,b) => (b.inMB+b.outMB)-(a.inMB+a.outMB)).slice(0,8);
  chartInstances['network'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top.map(i => i.name),
      datasets: [
        { label:'수신 (MB)', data: top.map(i => i.inMB.toFixed(1)), backgroundColor:'rgba(59,130,246,0.6)', borderRadius:3 },
        { label:'송신 (MB)', data: top.map(i => i.outMB.toFixed(1)), backgroundColor:'rgba(34,197,94,0.6)', borderRadius:3 }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:true,
      plugins:{ legend:{ labels:{ color:'#8b949e', font:{size:11} } },
                tooltip:{ backgroundColor:'#1c2230', borderColor:'#2a3347', borderWidth:1, titleColor:'#e6edf3', bodyColor:'#8b949e' } },
      scales:{
        x:{ ticks:{color:'#4a5568',font:{size:9}}, grid:{color:'#1e2a3a'} },
        y:{ ticks:{color:'#4a5568',font:{size:10}}, grid:{color:'#1e2a3a'} }
      }
    }
  });
}

// ===== SERVERS =====
async function renderServers(filter = 'all') {
  const list = document.getElementById('server-list');
  if (!list) return;
  const servers = state.devices.filter(d => d.type === 'server');
  if (servers.length === 0) {
    list.innerHTML = '<div style="color:var(--text-muted);padding:16px">등록된 서버가 없습니다.</div>';
    return;
  }
  const filtered = filter === 'all' ? servers : servers.filter(d => deviceStatus(d) === filter);
  list.innerHTML = filtered.map(d => {
    const status = deviceStatus(d);
    const m = getLive(d)?.metrics;
    const cpu  = m?.cpu_pct  ?? null;
    const mem  = m?.mem_pct  ?? null;
    const disk = m?.disks ? Math.max(...m.disks.map(x => x.used_pct), 0) : null;
    const upIf = (m?.interfaces||[]).filter(i=>i.status==='up').length;
    const dataTag = m ? '' : '<span style="color:var(--text-muted);font-size:10px">수집 대기중</span>';
    return `<div class="server-row status-${status}" onclick="showServerDetail(${d.id})">
      <div>
        <div class="server-name">${d.name}</div>
        <div class="server-ip">${d.ip_address}</div>
        <div style="margin-top:3px"><span class="badge ${badgeCls(status)}">${statusLabel(status)}</span></div>
      </div>
      ${cpu !== null ? metricBar('CPU', cpu, cpu>90?'critical':cpu>75?'warning':'normal') : metricBarEmpty('CPU')}
      ${mem !== null ? metricBar('Memory', mem, mem>85?'critical':mem>75?'warning':'normal') : metricBarEmpty('Memory')}
      ${disk !== null ? metricBar('Disk', disk, disk>90?'critical':disk>80?'warning':'normal') : metricBarEmpty('Disk')}
      <div class="metric-bar-wrap">
        <div class="metric-label"><span>네트워크</span></div>
        <div style="font-size:11px;color:var(--text-secondary)">${m ? (upIf+'개 포트 활성') : '--'}</div>
      </div>
      <div style="font-size:11px;color:var(--text-muted)">${d.os_version||'--'}</div>
      <button class="btn-sm" onclick="event.stopPropagation();showServerDetail(${d.id})">상세보기</button>
    </div>`;
  }).join('');
}

function metricBar(label, val, cls) {
  return `<div class="metric-bar-wrap">
    <div class="metric-label"><span>${label}</span><span>${val.toFixed(0)}%</span></div>
    <div class="metric-bar"><div class="metric-fill ${cls}" style="width:${Math.min(val,100)}%"></div></div>
  </div>`;
}
function metricBarEmpty(label) {
  return `<div class="metric-bar-wrap">
    <div class="metric-label"><span>${label}</span><span style="color:var(--text-muted)">--</span></div>
    <div class="metric-bar"><div class="metric-fill normal" style="width:0%"></div></div>
  </div>`;
}

async function showServerDetail(id) {
  const device = state.devices.find(d => d.id === id);
  if (!device) return;
  const m = getLive(device)?.metrics || {};
  const cpu  = m.cpu_pct  ?? null;
  const mem  = m.mem_pct  ?? null;
  const disks = m.disks || [];
  const disk = disks.length > 0 ? Math.max(...disks.map(x => x.used_pct), 0) : null;
  const upIf = (m.interfaces||[]).filter(i=>i.status==='up').length;

  document.getElementById('detail-server-name').textContent = `${device.name} (${device.ip_address})`;
  document.getElementById('detail-metrics').innerHTML = [
    { label:'CPU',     val: cpu  !== null ? cpu.toFixed(1)+'%'  : '--', color: cpu>90?'var(--red)':cpu>75?'var(--yellow)':'var(--green)' },
    { label:'Memory',  val: mem  !== null ? mem.toFixed(1)+'%'  : '--', color: mem>85?'var(--red)':mem>75?'var(--yellow)':'var(--green)' },
    { label:'Disk 최대', val: disk !== null ? disk.toFixed(1)+'%' : '--', color: disk>90?'var(--red)':disk>80?'var(--yellow)':'var(--green)' },
    { label:'인터페이스', val: m.interfaces ? upIf+'개 활성' : '--', color: 'var(--accent)' },
  ].map(x => `<div class="detail-metric">
    <div class="detail-metric-val" style="color:${x.color}">${x.val}</div>
    <div class="detail-metric-lbl">${x.label}</div>
  </div>`).join('');

  await renderDetailCharts(device);

  const processes = m.processes || [];
  document.getElementById('process-tbody').innerHTML = processes.length > 0
    ? processes.map(p => `<tr>
        <td>${p.name}</td><td style="font-family:var(--mono)">${p.pid}</td>
        <td>${(p.cpu_centisec/100).toFixed(1)}s</td>
        <td>${(p.mem_kb/1024).toFixed(1)} MB</td>
        <td><span class="badge ok">running</span></td></tr>`).join('')
    : `<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">${
        device.snmp_version === 'agent' ? '프로세스 데이터 없음 (에이전트 수집 대기중)' : '프로세스 데이터 없음 (hrSWRun 미응답)'
      }</td></tr>`;

  document.getElementById('server-detail').style.display = 'block';
  selectedServerId = id;
}

showServerDetail = async function(id) {
  const device = state.devices.find(d => d.id === id);
  if (!device) return;
  const m = getLive(device)?.metrics || {};
  const cpu  = m.cpu_pct  ?? null;
  const mem  = m.mem_pct  ?? null;
  const disks = m.disks || [];
  const disk = disks.length > 0 ? Math.max(...disks.map(x => x.used_pct), 0) : null;
  const upIf = (m.interfaces||[]).filter(i=>i.status==='up').length;

  document.getElementById('detail-server-name').textContent = `${device.name} (${device.ip_address})`;
  document.getElementById('detail-metrics').innerHTML = [
    { label:'CPU', val: cpu !== null ? cpu.toFixed(1)+'%' : '--', color: cpu>90?'var(--red)':cpu>75?'var(--yellow)':'var(--green)' },
    { label:'Memory', val: mem !== null ? mem.toFixed(1)+'%' : '--', color: mem>85?'var(--red)':mem>75?'var(--yellow)':'var(--green)' },
    { label:'Disk 최대', val: disk !== null ? disk.toFixed(1)+'%' : '--', color: disk>90?'var(--red)':disk>80?'var(--yellow)':'var(--green)', click:'focusDiskDetail()' },
    { label:'인터페이스', val: m.interfaces ? upIf+'개 활성' : '--', color: 'var(--accent)' },
  ].map(x => `<div class="detail-metric"${x.click ? ` onclick="${x.click}" style="cursor:pointer"` : ''}>
    <div class="detail-metric-val" style="color:${x.color}">${x.val}</div>
    <div class="detail-metric-lbl">${x.label}</div>
  </div>`).join('');

  await renderDetailCharts(device);

  const diskTbody = document.getElementById('disk-tbody');
  if (diskTbody) diskTbody.innerHTML = renderDiskRows(device, disks);

  const processes = m.processes || [];
  document.getElementById('process-tbody').innerHTML = processes.length > 0
    ? processes.map(p => `<tr>
        <td>${p.name}</td><td style="font-family:var(--mono)">${p.pid}</td>
        <td>${(p.cpu_centisec/100).toFixed(1)}s</td>
        <td>${(p.mem_kb/1024).toFixed(1)} MB</td>
        <td><span class="badge ok">running</span></td></tr>`).join('')
    : '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">프로세스 데이터 없음 (hrSWRun 미응답)</td></tr>';

  document.getElementById('server-detail').style.display = 'block';
  selectedServerId = id;
};

async function renderDetailCharts(device) {
  destroyChart('detail-cpu'); destroyChart('detail-mem');
  const [cpuH, memH] = await Promise.all([
    fetchHistory(device.id, 'cpu_pct', 1),
    fetchHistory(device.id, 'mem_pct', 1)
  ]);
  [['cpu', cpuH, '#3B82F6', 'rgba(59,130,246,0.1)'],
   ['mem', memH, '#a855f7', 'rgba(168,85,247,0.1)']].forEach(([key, hist, color, bg]) => {
    const ctx = document.getElementById(`detail-${key}-chart`);
    if (!ctx) return;
    if (hist.length === 0) {
      chartInstances[`detail-${key}`] = makeEmptyChart(ctx, key.toUpperCase()+'%', 0, 100);
      return;
    }
    chartInstances[`detail-${key}`] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: hist.map(h => fmtChartTime(h.time)),
        datasets: [{ label: key.toUpperCase()+'%', data: hist.map(h => h.avg),
          borderColor: color, backgroundColor: bg, fill:true, borderWidth:1.5, pointRadius:0, tension:0.4 }]
      },
      options: chartOptions(key.toUpperCase()+'%', 0, 100)
    });
  });
}

function closeDetail() { document.getElementById('server-detail').style.display = 'none'; }

function filterServers(q) {
  document.querySelectorAll('.server-row').forEach(row => {
    const name = row.querySelector('.server-name')?.textContent.toLowerCase() || '';
    row.style.display = name.includes(q.toLowerCase()) ? '' : 'none';
  });
}

function filterByStatus(status, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderServers(status);
}

// ===== SWITCHES =====
async function renderSwitches() {
  const listEl = document.getElementById('switch-list-items');
  if (!listEl) return;
  const switches = state.devices.filter(d => d.type === 'switch');
  if (switches.length === 0) {
    listEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:12px">등록된 스위치 없음</div>';
    return;
  }
  listEl.innerHTML = switches.map(sw => {
    const st = deviceStatus(sw);
    return `<div class="switch-list-item ${selectedSwitchId===sw.id?'active':''}" onclick="selectSwitch(${sw.id})">
      <span class="dot ${st==='critical'?'red':st==='warning'?'yellow':'green'}"></span>
      <div>
        <div style="font-size:12px;font-weight:600">${sw.name}</div>
        <div style="font-size:10px;color:var(--text-muted)">${sw.ip_address}</div>
      </div>
    </div>`;
  }).join('');

  const targetId = selectedSwitchId || switches[0]?.id;
  if (targetId) selectSwitch(targetId);
}

function selectSwitch(id) {
  selectedSwitchId = id;
  const device = state.devices.find(d => d.id === id);
  if (!device) return;
  const ifaces = sortSwitchPorts(getLive(device)?.metrics?.interfaces || []);

  document.getElementById('switch-detail-name').textContent =
    `${device.name} 상세 (${device.os_version||''})`;

  document.getElementById('switch-port-map').innerHTML = ifaces.length > 0
    ? ifaces.map(p => {
        const label = portShortLabel(p);
        const name = portDisplayName(p);
        const alias = p.alias ? ` | Alias ${escapeHtml(p.alias)}` : '';
        return `<div class="port-cell ${p.status}" title="${escapeHtml(name)} | ${p.status} | ${p.speed_mbps}M${alias}">${escapeHtml(label)}</div>`;
      }).join('')
    : '<div style="color:var(--text-muted);font-size:11px;padding:8px">포트 데이터 없음 - SNMP 수집 대기중</div>';

  const portTableBody = document.getElementById('port-table-body');
  const portTableHead = portTableBody?.closest('table')?.querySelector('thead');
  if (portTableHead) {
    const table = portTableBody.closest('table');
    const header = table?.previousElementSibling?.classList?.contains('card-header')
      ? table.previousElementSibling
      : document.querySelector('#page-switches .switch-detail-panel > .card-header[style*="margin-top"]');
    header?.querySelector('#reset-switch-errors-btn')?.remove();
    portTableHead.innerHTML = '<tr><th>포트</th><th>ifIndex</th><th>상태</th><th>속도</th><th>수신 누적</th><th>송신 누적</th><th>Alias</th></tr>';
  }

  portTableBody.innerHTML = ifaces.map(p => `
    <tr>
      <td style="font-family:var(--mono)" title="ifIndex ${p.index} / ${escapeHtml(p.descr || '')}">${escapeHtml(portDisplayName(p))}</td>
      <td style="font-family:var(--mono);color:var(--text-muted)">${p.index}</td>
      <td><span class="badge ${p.status==='up'?'ok':p.status==='down'?'critical':'info'}">${p.status}</span></td>
      <td>${p.speed_mbps>0?p.speed_mbps+'M':'--'}</td>
      <td>${p.status==='up'?(p.in_octets/1024/1024).toFixed(1)+' MB':'--'}</td>
      <td>${p.status==='up'?(p.out_octets/1024/1024).toFixed(1)+' MB':'--'}</td>
      <td style="color:var(--text-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(p.alias || '')}">${escapeHtml(p.alias || '--')}</td>
    </tr>`).join('');

  renderSwitchCharts(ifaces);

  document.querySelectorAll('.switch-list-item').forEach((el, i) => {
    const swArr = state.devices.filter(d => d.type === 'switch');
    el.classList.toggle('active', swArr[i]?.id === id);
  });
}

async function resetSwitchErrorCounters(deviceId) {
  if (!confirm('스위치 포트 오류 카운트 수집은 더 이상 사용하지 않습니다. 계속 진행하시겠습니까?')) return;
  try {
    await api('/switches/' + deviceId + '/error-counters/reset', 'POST');
    showToast('스위치 오류 기준값을 초기화했습니다.');
    await loadAll();
    renderPage(currentPage);
  } catch (e) {
    showToast('오류 카운트 초기화 실패: ' + e.message);
  }
}

function renderSwitchCharts(ifaces) {
  destroyChart('sw-in'); destroyChart('sw-out');
  const upIf = ifaces.filter(i => i.status === 'up');
  [['sw-traffic-in','수신 (MB)',upIf.map(i=>({name:i.name,val:i.in_octets/1024/1024})),'rgba(59,130,246,0.6)'],
   ['sw-traffic-out','송신 (MB)',upIf.map(i=>({name:i.name,val:i.out_octets/1024/1024})),'rgba(34,197,94,0.6)']
  ].forEach(([cid, label, data, color]) => {
    const ctx = document.getElementById(cid);
    if (!ctx) return;
    const key = cid === 'sw-traffic-in' ? 'sw-in' : 'sw-out';
    if (data.length === 0) { chartInstances[key] = makeEmptyChart(ctx, label, 0, 100); return; }
    const top = data.sort((a,b)=>b.val-a.val).slice(0,8);
    chartInstances[key] = new Chart(ctx, {
      type: 'bar',
      data: { labels: top.map(d=>d.name), datasets: [{ label, data: top.map(d=>d.val.toFixed(1)), backgroundColor: color, borderRadius:3 }] },
      options: { responsive:true, maintainAspectRatio:true,
        plugins:{ legend:{display:false} },
        scales:{ x:{ticks:{color:'#8b949e',font:{size:9}},grid:{color:'#1e2a3a'}}, y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#1e2a3a'}} } }
    });
  });
}

// ===== ENVIRONMENT =====
async function renderEnvironment() {
  const envDev = state.devices.find(isEnvironmentDevice);
  const upsDev = state.devices.find(d => d.type === 'ups');

  // Environment gauges
  const envLive = getEnvironmentLive(envDev);
  const envM = envLive?.metrics || null;

  if (envM && envM.temp_c !== null && envM.temp_c !== undefined) {
    drawGauge('gauge-temp', envM.temp_c, 15, 35, 18, 27);
    drawGauge('gauge-humi', envM.humidity_pct || 0, 20, 80, 40, 60);
    setEl('gauge-temp-val', envM.temp_c.toFixed(1) + '°C');
    setEl('gauge-humi-val', (envM.humidity_pct || 0).toFixed(0) + '%');
  } else {
    drawGaugeEmpty('gauge-temp', envDev ? 'SNMP 수집 대기중' : '장비 미등록');
    drawGaugeEmpty('gauge-humi', envDev ? 'SNMP 수집 대기중' : '장비 미등록');
    setEl('gauge-temp-val', '--');
    setEl('gauge-humi-val', '--');
  }

  // UPS metrics
  const upsM = upsDev ? (getLive(upsDev)?.metrics || null) : null;
  const upsFields = [
    ['ups-batt',    upsM ? (upsM.battery_pct??0).toFixed(0)+'%'      : '--'],
    ['ups-load',    upsM ? (upsM.load_pct||0).toFixed(0)+'%'         : '--'],
    ['ups-input',   upsM ? (upsM.input_v||0).toFixed(0)+'V'          : '--'],
    ['ups-output',  upsM ? (upsM.output_v||0).toFixed(0)+'V'         : '--'],
    ['ups-runtime', upsM ? (upsM.runtime_min||0).toFixed(0)+'분'     : '--'],
    ['ups-temp-val',upsM ? (upsM.temp_c||0).toFixed(0)+'°C'          : '--'],
    ['ups-status',  upsM ? (upsM.status || 'ONLINE')                  : '--']
  ];
  upsFields.forEach(([id, val]) => setEl(id, val));

  // History charts
  await renderEnvHistoryChart(envDev, envM);
  await renderUPSHistoryChart(upsDev, upsM);
}

function drawGaugeEmpty(canvasId, msg) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#2a3347';
  ctx.roundRect(0, 0, canvas.width, canvas.height, 4);
  ctx.fill();
  ctx.fillStyle = '#4a5568';
  ctx.font = '11px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(msg, canvas.width / 2, canvas.height / 2);
}

function drawGauge(canvasId, value, min, max, okMin, okMax) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = canvas.width/2, cy = canvas.height/2, r = 70;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const start = Math.PI*0.75, end = Math.PI*2.25, total = end-start;
  const pct = Math.min(Math.max((value-min)/(max-min), 0), 1);
  const valueAngle = start + total*pct;

  ctx.beginPath(); ctx.arc(cx,cy,r,start,end);
  ctx.strokeStyle='#2a3347'; ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();

  const okS=(okMin-min)/(max-min), okE=(okMax-min)/(max-min);
  ctx.beginPath(); ctx.arc(cx,cy,r,start+total*okS,start+total*okE);
  ctx.strokeStyle='rgba(34,197,94,0.2)'; ctx.lineWidth=14; ctx.stroke();

  ctx.beginPath(); ctx.arc(cx,cy,r,start,valueAngle);
  ctx.strokeStyle=value>okMax?'#ef4444':value<okMin?'#3B82F6':'#22c55e';
  ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();

  ctx.save(); ctx.translate(cx,cy); ctx.rotate(valueAngle);
  ctx.beginPath(); ctx.moveTo(0,0); ctx.lineTo(r-18,0);
  ctx.strokeStyle='white'; ctx.lineWidth=2; ctx.stroke(); ctx.restore();

  ctx.beginPath(); ctx.arc(cx,cy,5,0,Math.PI*2); ctx.fillStyle='white'; ctx.fill();
}

async function renderEnvHistoryChart(envDev, envM) {
  const ctx = document.getElementById('env-history-chart');
  if (!ctx) return;
  destroyChart('env-hist');
  if (!envDev) { chartInstances['env-hist'] = makeEmptyChart(ctx, '온도/습도'); return; }

  const [tempH, humiH] = await Promise.all([
    fetchHistory(envDev.id, 'temp_c', 6),
    fetchHistory(envDev.id, 'humidity_pct', 6)
  ]);
  const longest = tempH.length >= humiH.length ? tempH : humiH;
  if (longest.length === 0) { chartInstances['env-hist'] = makeEmptyChart(ctx, '온도/습도'); return; }

  chartInstances['env-hist'] = new Chart(ctx, {
    type:'line',
    data:{ labels:longest.map(h=>fmtChartTime(h.time)), datasets:[
      ...(tempH.length>0?[{label:'온도 (°C)',data:tempH.map(h=>h.avg),borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,0.08)',fill:true,borderWidth:1.5,pointRadius:0,tension:0.4,yAxisID:'y'}]:[]),
      ...(humiH.length>0?[{label:'습도 (%)',data:humiH.map(h=>h.avg),borderColor:'#3B82F6',backgroundColor:'rgba(59,130,246,0.08)',fill:true,borderWidth:1.5,pointRadius:0,tension:0.4,yAxisID:'y1'}]:[])
    ]},
    options:{responsive:true,maintainAspectRatio:true,
      plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}},
      scales:{
        x:{ticks:{color:'#4a5568',font:{size:10}},grid:{color:'#1e2a3a'}},
        y:{ticks:{color:'#ef4444',font:{size:10}},grid:{color:'#1e2a3a'},min:15,max:35,title:{display:true,text:'°C',color:'#ef4444'}},
        y1:{position:'right',ticks:{color:'#3B82F6',font:{size:10}},grid:{drawOnChartArea:false},min:20,max:80,title:{display:true,text:'%',color:'#3B82F6'}}
      }}
  });
}

async function renderUPSHistoryChart(upsDev, upsM) {
  const ctx = document.getElementById('ups-history-chart');
  if (!ctx) return;
  destroyChart('ups-hist');
  if (!upsDev) { chartInstances['ups-hist'] = makeEmptyChart(ctx, 'UPS'); return; }

  const [battH, loadH] = await Promise.all([
    fetchHistory(upsDev.id, 'battery_pct', 6),
    fetchHistory(upsDev.id, 'load_pct', 6)
  ]);
  const longest = battH.length >= loadH.length ? battH : loadH;
  if (longest.length === 0) { chartInstances['ups-hist'] = makeEmptyChart(ctx, 'UPS'); return; }

  chartInstances['ups-hist'] = new Chart(ctx, {
    type:'line',
    data:{ labels:longest.map(h=>fmtChartTime(h.time)), datasets:[
      ...(battH.length>0?[{label:'배터리 (%)',data:battH.map(h=>h.avg),borderColor:'#22c55e',borderWidth:1.5,pointRadius:0,tension:0.4}]:[]),
      ...(loadH.length>0?[{label:'부하율 (%)',data:loadH.map(h=>h.avg),borderColor:'#f59e0b',borderWidth:1.5,pointRadius:0,tension:0.4}]:[])
    ]},
    options: chartOptions('%', 0, 100)
  });
}

// ===== PROCESSES =====
async function renderProcesses() {
  const tbody = document.getElementById('all-process-tbody');
  if (!tbody) return;
  const rows = [];
  state.devices.filter(d => d.type === 'server').forEach(d => {
    const processes = getLive(d)?.metrics?.processes || [];
    if (processes.length === 0) {
      rows.push(`<tr><td style="color:var(--accent)">${d.name}</td>
        <td colspan="7" style="color:var(--text-muted)">
          ${getLive(d)
            ? (d.snmp_version === 'agent' ? '프로세스 데이터 없음 (에이전트 수집 대기중)' : '프로세스 데이터 없음 (hrSWRun 미응답)')
            : (d.snmp_version === 'agent' ? '에이전트 수집 대기중' : 'SNMP 수집 대기중')}
        </td></tr>`);
    } else {
      processes.forEach(p => rows.push(`<tr>
        <td>${d.name}</td><td>${p.name}</td>
        <td style="font-family:var(--mono)">${p.pid}</td>
        <td>${(p.cpu_centisec/100).toFixed(1)}s</td>
        <td>${(p.mem_kb/1024).toFixed(1)} MB</td>
        <td>--</td>
        <td><span class="badge ok">running</span></td>
        <td><button class="btn-sm" style="color:var(--red)">중지</button></td>
      </tr>`));
    }
  });
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">서버 미등록</td></tr>';
    return;
  }
  tbody.innerHTML = rows.join('');
  renderProcessChart();
}

function renderProcessChart() {
  const ctx = document.getElementById('proc-cpu-chart');
  if (!ctx) return;
  destroyChart('proc-cpu');
  const all = [];
  state.devices.filter(d => d.type === 'server').forEach(d => {
    (getLive(d)?.metrics?.processes || []).forEach(p =>
      all.push({ label:`${d.name}:${p.name}`, cpu: p.cpu_centisec/100 })
    );
  });
  if (all.length === 0) { chartInstances['proc-cpu'] = makeEmptyChart(ctx, 'CPU'); return; }
  all.sort((a,b) => b.cpu-a.cpu);
  const top = all.slice(0,8);
  chartInstances['proc-cpu'] = new Chart(ctx, {
    type:'bar',
    data:{ labels:top.map(p=>p.label), datasets:[{ label:'CPU(s)', data:top.map(p=>p.cpu.toFixed(1)),
      backgroundColor:top.map(p=>p.cpu>30?'rgba(239,68,68,0.6)':p.cpu>15?'rgba(245,158,11,0.6)':'rgba(34,197,94,0.6)'), borderRadius:3 }] },
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#8b949e',font:{size:9}},grid:{color:'#1e2a3a'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#1e2a3a'}}}}
  });
}

// ===== SECURITY =====
async function renderSecurity() {
  if (!state.cves._loaded) { await loadCVEs(); }
  const counts = state.cves.counts || {};
  setEl('cve-count-critical', counts.CRITICAL ?? 0);
  setEl('cve-count-high',     counts.HIGH     ?? 0);
  setEl('cve-count-medium',   counts.MEDIUM   ?? 0);
  setEl('cve-count-low',      counts.LOW      ?? 0);
  if (state.cves.last_updated) {
    setEl('nvd-update-date', state.cves.last_updated.slice(0, 10));
  }
  renderCVSSChart();
  renderAffectedChart();
  renderCVETable();
}

// ===== SCRIPT CHECK RESULTS =====
async function renderSecurityChecks() {
  if (!state.checkResults._loaded) { await loadCheckResults(); }
  const summary = state.checkResults.summary || {};
  setEl('check-summary-runs', summary.run_count ?? 0);
  setEl('check-summary-servers', summary.server_count ?? 0);
  setEl('check-summary-fail', summary.fail_count ?? 0);
  setEl('check-summary-warn', summary.warn_count ?? 0);
  renderCheckRuns();
  renderCheckServerSummary();
}

function checkStatusBadge(status) {
  if (status === 'fail') return '<span class="badge critical">취약</span>';
  if (status === 'warn') return '<span class="badge medium">확인필요</span>';
  if (status === 'pass') return '<span class="badge ok">양호</span>';
  return '<span class="badge info">N/A</span>';
}

function renderCheckRuns() {
  const tbody = document.getElementById('check-runs-tbody');
  if (!tbody) return;
  const rows = state.checkResults.latest_runs || [];
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px">저장된 점검 결과 없음</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const fileName = r.report_file || r.report_title || '--';
    return `<tr>
      <td style="font-family:var(--mono);white-space:nowrap;font-size:11px">${new Date(r.completed_at).toLocaleString('ko-KR')}</td>
      <td><span class="badge info">${r.run_type}</span></td>
      <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${fileName}">${fileName}</td>
      <td><span class="badge critical">${r.fail_count || 0}</span> <span class="badge medium">${r.warn_count || 0}</span> <span class="badge info">${r.result_count || 0}</span></td>
      <td style="white-space:nowrap">
        <button class="btn-sm" onclick="showCheckRunResults(${r.id}, '${String(r.report_title || '').replace(/'/g, "\\'")}')">상세</button>
        ${r.report_file_id ? `<button class="btn-sm" onclick="downloadCheckReport(${r.report_file_id}, '${String(fileName).replace(/'/g, "\\'")}')">원본</button>` : ''}
        ${isAdminUser() ? `<button class="btn-sm" style="color:var(--red)" onclick="deleteCheckRun(${r.id})">삭제</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

function renderCheckServerSummary() {
  const tbody = document.getElementById('check-server-summary-tbody');
  if (!tbody) return;
  const rows = state.checkResults.server_summary || [];
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px">서버별 결과 없음</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `<tr>
    <td style="font-weight:600">${r.hostname || '--'}</td>
    <td style="font-family:var(--mono)">${r.ip_address || '--'}</td>
    <td><span class="badge critical">${r.fail_count || 0}</span></td>
    <td><span class="badge medium">${r.warn_count || 0}</span></td>
    <td style="font-size:11px;color:var(--text-muted)">${r.last_checked_at ? new Date(r.last_checked_at).toLocaleString('ko-KR') : '--'}</td>
  </tr>`).join('');
}

async function showCheckRunResults(id, title) {
  const tbody = document.getElementById('check-results-tbody');
  if (!tbody) return;
  setEl('check-detail-title', `점검 상세 결과 - ${title || id}`);
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">불러오는 중...</td></tr>';
  try {
    const rows = await api(`/security/checks/runs/${id}/results`);
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">상세 결과 없음</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `<tr>
      <td>${checkStatusBadge(r.result_status)}</td>
      <td style="font-weight:600">${r.hostname || '--'}</td>
      <td><div style="font-family:var(--mono);color:var(--accent);font-size:11px">${r.code}</div>${r.item_name || ''}</td>
      <td>${r.category || '--'}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.result_value || r.evidence || ''}">${r.result_value || r.evidence || '--'}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.recommendation || ''}">${r.recommendation || '--'}</td>
    </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--red);padding:24px">상세 결과 로드 실패</td></tr>';
  }
}

async function uploadCheckReport() {
  if (!isAdminUser()) { showToast('관리자 권한이 필요합니다.'); return; }
  const file = document.getElementById('check-report-file')?.files?.[0];
  if (!file) { showToast('업로드할 결과 파일을 선택하세요.'); return; }
  const form = new FormData();
  form.append('report_file', file);
  form.append('run_type', document.getElementById('check-upload-type')?.value || 'security');
  const token = localStorage.getItem('ng_token') || '';
  try {
    const r = await fetch('/api/security/checks/reports', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: form
    });
    if (!r.ok) throw new Error(`${r.status}`);
    const result = await r.json();
    await loadCheckResults();
    renderSecurityChecks();
    showToast(`결과 저장 완료: ${result.imported_results || 0}건`);
  } catch (e) {
    showToast('결과 업로드 실패: ' + e.message);
  }
}

async function downloadCheckReport(fileId, filename) {
  const token = localStorage.getItem('ng_token') || '';
  try {
    const r = await fetch(`/api/security/checks/files/${fileId}/download`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!r.ok) throw new Error(`${r.status}`);
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'report';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast('원본 다운로드 실패: ' + e.message);
  }
}

async function deleteCheckRun(id) {
  if (!confirm('이 점검 결과를 삭제하시겠습니까?')) return;
  try {
    await api(`/security/checks/runs/${id}`, 'DELETE');
    await loadCheckResults();
    renderSecurityChecks();
    showToast('점검 결과가 삭제되었습니다.');
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

function renderCVSSChart() {
  const ctx = document.getElementById('cvss-chart');
  if (!ctx) return;
  destroyChart('cvss');
  const bins = [0,0,0,0,0,0,0,0,0,0];
  (state.cves.items||[]).forEach(c => { bins[Math.min(9,Math.floor(c.cvss))]++; });
  chartInstances['cvss'] = new Chart(ctx, {
    type:'bar',
    data:{ labels:['0-1','1-2','2-3','3-4','4-5','5-6','6-7','7-8','8-9','9-10'],
      datasets:[{data:bins, backgroundColor:['#22c55e','#22c55e','#22c55e','#22c55e','#f59e0b','#f59e0b','#f59e0b','#f97316','#ef4444','#ef4444'], borderRadius:3}] },
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#1e2a3a'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#1e2a3a'},stepSize:1}}}
  });
}

function renderAffectedChartLegacy() {
  const ctx = document.getElementById('affected-chart');
  if (!ctx) return;
  destroyChart('affected');
  const cnt = {};
  (state.cves.items||[]).forEach(c => (c.affected_devices||[c.device]).forEach(d => { cnt[d]=(cnt[d]||0)+1; }));
  const devs = Object.entries(cnt);
  if (devs.length === 0) { chartInstances['affected'] = makeEmptyChart(ctx, '영향 장비'); return; }
  chartInstances['affected'] = new Chart(ctx, {
    type:'doughnut',
    data:{ labels:devs.map(d=>d[0]), datasets:[{data:devs.map(d=>d[1]),backgroundColor:['#3B82F6','#22c55e','#f59e0b','#ef4444','#a855f7','#06b6d4']}] },
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:10}}}}}
  });
}

function renderCVETableLegacy() {
  const tbody = document.getElementById('cve-tbody');
  if (!tbody) return;
  const items = state.cves.items||[];
  if (items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">CVE 데이터 없음 - data/nvd_cache/에 NVD 피드 파일 필요</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(c => `
    <tr>
      <td style="font-family:var(--mono);font-weight:600;color:var(--accent)">${c.cve_id}</td>
      <td><span class="badge ${c.severity.toLowerCase()}">${c.severity}</span></td>
      <td style="font-weight:700;color:${c.cvss>=9?'var(--red)':c.cvss>=7?'var(--orange)':'var(--yellow)'}">${c.cvss.toFixed(1)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${c.cwe||'--'}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.description}">${c.description}</td>
      <td>${(c.affected_devices||[c.device]).map(d=>`<span class="badge info" style="margin-right:2px">${d}</span>`).join('')}</td>
      <td><button class="btn-sm" onclick="showCVEDetail('${c.cve_id}')">상세</button></td>
    </tr>`).join('');
}

// ===== EVENTS =====
let _eventSevFilter = 'all';

async function renderEventsLegacy(filter) {
  if (filter !== undefined) _eventSevFilter = filter;
  const tbody = document.getElementById('events-tbody');
  if (!tbody) return;

  const searchVal = (document.getElementById('event-search')?.value || '').toLowerCase();
  const dateFrom  = document.getElementById('event-date-from')?.value;
  const dateTo    = document.getElementById('event-date-to')?.value;

  let list = _eventSevFilter === 'all'
    ? state.events
    : state.events.filter(e => e.severity === _eventSevFilter);

  if (searchVal) {
    list = list.filter(e =>
      (e.message || '').toLowerCase().includes(searchVal) ||
      (e.device_name || '').toLowerCase().includes(searchVal) ||
      (e.category || '').toLowerCase().includes(searchVal)
    );
  }
  if (dateFrom) list = list.filter(e => new Date(e.time) >= new Date(dateFrom));
  if (dateTo)   list = list.filter(e => new Date(e.time) <= new Date(dateTo + 'T23:59:59'));

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px">이벤트 없음</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(e => {
    const hasId   = e.id !== undefined && e.id !== null;
    const devName = e.device_name || e.device || '--';
    const sevCls  = e.severity === 'critical' ? 'critical' : e.severity === 'warning' ? 'medium' : 'info';
    const stCls   = e.status === 'active' ? 'critical' : e.status === 'acknowledged' ? 'medium' : 'ok';
    const stLabel = e.status === 'active' ? '활성' : e.status === 'acknowledged' ? '확인됨' : '해결됨';
    const ackBtns = hasId
      ? `<button class="btn-sm" onclick="ackEvent(${e.id},'acknowledge')" ${e.status !== 'active' ? 'disabled style="opacity:0.4"' : ''}>확인</button>
         <button class="btn-sm" onclick="ackEvent(${e.id},'resolve')" ${e.status === 'resolved' ? 'disabled style="opacity:0.4"' : ''}>해결</button>
         <button class="btn-sm" style="color:var(--red)" onclick="deleteEvent(${e.id})">삭제</button>`
      : `<span style="color:var(--text-muted);font-size:11px">대기</span>`;
    return `<tr>
      <td style="font-family:var(--mono);white-space:nowrap;font-size:11px">${new Date(e.time).toLocaleString('ko-KR')}</td>
      <td><span class="badge ${sevCls}">${e.severity.toUpperCase()}</span></td>
      <td style="font-weight:600">${devName}</td>
      <td style="color:var(--text-muted)">${e.category || '--'}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.message}">${e.message}</td>
      <td><span class="badge ${stCls}">${stLabel}</span></td>
      <td style="white-space:nowrap">${ackBtns}</td>
    </tr>`;
  }).join('');
}

async function ackEvent(id, action) {
  try {
    await api('/events/ack', 'POST', { event_id: id, action });
    const ev = state.events.find(e => e.id === id);
    if (ev) ev.status = action === 'acknowledge' ? 'acknowledged' : 'resolved';
    renderEvents();
    updateBadges();
    updateAlertBanner();
    showToast(action === 'acknowledge' ? '이벤트 확인 처리됨' : '이벤트 해결 처리됨');
  } catch (e) {
    showToast('처리 실패: ' + e.message);
  }
}

async function deleteEvent(id) {
  if (!confirm('이 이벤트를 영구 삭제합니까?')) return;
  try {
    await api(`/events/${id}`, 'DELETE');
    state.events = state.events.filter(e => e.id !== id);
    renderEvents();
    updateBadges();
    updateAlertBanner();
    showToast('이벤트 삭제 완료');
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

async function deleteEvents(filter) {
  const labels = { all: '모든 이벤트', resolved: '해결된 이벤트', acknowledged: '확인된 이벤트' };
  const label  = labels[filter] || '이벤트';
  const count  = filter === 'all' ? state.events.length
               : state.events.filter(e => e.status === filter).length;
  if (count === 0) { showToast(`삭제할 ${label}이 없습니다`); return; }
  if (!confirm(`${label} ${count}건을 영구 삭제합니까?\n이 작업은 되돌릴 수 없습니다.`)) return;
  try {
    const qs  = filter === 'all' ? '' : `?status=${filter}`;
    const res = await api(`/events/bulk${qs}`, 'DELETE');
    await loadAll();
    renderEvents();
    updateAlertBanner();
    showToast(`${res.deleted || 0}건 삭제 완료`);
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

function filterEvents(filter, btn) {
  document.querySelectorAll('#page-events .filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderEvents(filter);
}

// ===== DEVICES =====
async function renderDevicesLegacy() {
  const tbody = document.getElementById('devices-tbody');
  if (!tbody) return;
  if (state.devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">등록된 장비 없음. 장비 추가 버튼을 클릭하세요.</td></tr>';
    return;
  }
  tbody.innerHTML = state.devices.map(d => {
    const st = deviceStatus(d);
    return `<tr>
      <td style="font-weight:600">${d.name}</td>
      <td>${TYPE_KO[d.type]||d.type}</td>
      <td style="font-family:var(--mono)">${d.ip_address}</td>
      <td><span class="badge info">${d.snmp_version}</span></td>
      <td style="font-family:var(--mono);color:var(--text-muted)">${d.community}</td>
      <td style="font-size:11px;color:var(--text-muted)">${d.os_version||'--'}</td>
      <td><span class="dot ${st==='critical'?'red':st==='warning'?'yellow':'green'}"></span> ${statusLabel(st)}</td>
      <td>
        <button class="btn-sm" onclick="editDevice(${d.id})">수정</button>
        <button class="btn-sm" style="color:var(--red)" onclick="deleteDevice(${d.id})">삭제</button>
      </td>
    </tr>`;
  }).join('');
}

async function deleteDevice(id) {
  const device = state.devices.find(d => d.id === id);
  if (!device || !confirm(`"${device.name}" 장비를 삭제하시겠습니까?`)) return;
  try {
    await api('/devices/' + id, 'DELETE');
    state.devices = state.devices.filter(d => d.id !== id);
    delete state.live[device.name];
    renderDevices();
    showToast(device.name + ' 삭제 완료');
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

function editDevice(id) {
  const d = state.devices.find(dev => dev.id === id);
  if (!d) return;
  editingDeviceId = id;
  document.getElementById('modal-title').textContent = '장비 수정';
  document.getElementById('modal-save-btn').textContent = '저장';
  document.getElementById('new-dev-name').value = d.name;
  document.getElementById('new-dev-type').value = d.type;
  document.getElementById('new-dev-ip').value = d.ip_address;
  document.getElementById('new-dev-snmp').value = d.snmp_version;
  document.getElementById('new-dev-community').value = d.community;
  document.getElementById('new-dev-v3-user').value = d.snmp_v3_user || '';
  document.getElementById('new-dev-v3-level').value = d.snmp_v3_security_level || 'authPriv';
  document.getElementById('new-dev-v3-auth-proto').value = d.snmp_v3_auth_protocol || 'SHA';
  document.getElementById('new-dev-v3-auth').value = d.snmp_v3_auth || '';
  document.getElementById('new-dev-v3-priv-proto').value = d.snmp_v3_priv_protocol || 'AES';
  document.getElementById('new-dev-v3-priv').value = d.snmp_v3_priv || '';
  updateSnmpV3Fields();
  document.getElementById('add-device-modal').style.display = 'flex';
}

// ===== MODAL =====
function updateSnmpV3Fields() {
  const isV3 = document.getElementById('new-dev-snmp')?.value === 'v3';
  const level = document.getElementById('new-dev-v3-level')?.value || 'authPriv';
  document.querySelectorAll('.snmp-v3-field').forEach(el => {
    el.style.display = isV3 ? 'block' : 'none';
  });
  document.querySelectorAll('.snmp-v3-auth-field').forEach(el => {
    el.style.display = isV3 && level !== 'noAuthNoPriv' ? 'block' : 'none';
  });
  document.querySelectorAll('.snmp-v3-priv-field').forEach(el => {
    el.style.display = isV3 && level === 'authPriv' ? 'block' : 'none';
  });
}

function showAddDevice() {
  editingDeviceId = null;
  document.getElementById('modal-title').textContent = '장비 추가';
  document.getElementById('modal-save-btn').textContent = '추가';
  document.getElementById('new-dev-name').value = '';
  document.getElementById('new-dev-type').value = 'server';
  document.getElementById('new-dev-ip').value = '';
  document.getElementById('new-dev-snmp').value = 'v2c';
  document.getElementById('new-dev-community').value = 'public';
  document.getElementById('new-dev-v3-user').value = '';
  document.getElementById('new-dev-v3-level').value = 'authPriv';
  document.getElementById('new-dev-v3-auth-proto').value = 'SHA';
  document.getElementById('new-dev-v3-auth').value = '';
  document.getElementById('new-dev-v3-priv-proto').value = 'AES';
  document.getElementById('new-dev-v3-priv').value = '';
  updateSnmpV3Fields();
  document.getElementById('add-device-modal').style.display = 'flex';
}

function closeModal(id) { document.getElementById(id).style.display = 'none'; }

async function saveDevice() {
  const name      = document.getElementById('new-dev-name').value.trim();
  const type      = document.getElementById('new-dev-type').value;
  const ip        = document.getElementById('new-dev-ip').value.trim();
  const snmp      = document.getElementById('new-dev-snmp').value;
  const community = document.getElementById('new-dev-community').value.trim();
  const v3User    = document.getElementById('new-dev-v3-user').value.trim();
  const v3Level   = document.getElementById('new-dev-v3-level').value;
  const v3AuthProto = document.getElementById('new-dev-v3-auth-proto').value;
  const v3Auth    = document.getElementById('new-dev-v3-auth').value.trim();
  const v3PrivProto = document.getElementById('new-dev-v3-priv-proto').value;
  const v3Priv    = document.getElementById('new-dev-v3-priv').value.trim();
  if (!name || !ip) { showToast('장비명과 IP 주소는 필수입니다.'); return; }
  if (snmp === 'v3' && !v3User) { showToast('SNMP v3 사용자는 필수입니다.'); return; }
  if (snmp === 'v3' && v3Level !== 'noAuthNoPriv' && !v3Auth) { showToast('SNMP v3 인증 비밀번호는 필수입니다.'); return; }
  if (snmp === 'v3' && v3Level === 'authPriv' && !v3Priv) { showToast('SNMP v3 암호화 비밀번호는 필수입니다.'); return; }
  const payload = {
    name,
    type,
    ip_address: ip,
    snmp_version: snmp,
    community,
    snmp_v3_user: snmp === 'v3' ? v3User : '',
    snmp_v3_security_level: snmp === 'v3' ? v3Level : '',
    snmp_v3_auth_protocol: snmp === 'v3' ? v3AuthProto : '',
    snmp_v3_auth: snmp === 'v3' ? v3Auth : '',
    snmp_v3_priv_protocol: snmp === 'v3' ? v3PrivProto : '',
    snmp_v3_priv: snmp === 'v3' ? v3Priv : ''
  };
  try {
    if (editingDeviceId !== null) {
      await api('/devices/' + editingDeviceId, 'PUT', payload);
      const idx = state.devices.findIndex(d => d.id === editingDeviceId);
      if (idx >= 0) Object.assign(state.devices[idx], payload);
      showToast(name + ' 수정 완료');
    } else {
      const result = await api('/devices', 'POST', payload);
      const existingIdx = state.devices.findIndex(d => Number(d.id) === Number(result.id) || d.name === name);
      const savedDevice = { id: result.id, ...payload, os_version: '', enabled: true };
      if (existingIdx >= 0) {
        Object.assign(state.devices[existingIdx], savedDevice);
      } else {
        state.devices.push(savedDevice);
      }
      showToast(name + ' 추가 완료');
    }
    renderDevices();
    closeModal('add-device-modal');
  } catch (e) {
    showToast('저장 실패: ' + e.message);
  }
}

// ===== ALERT PANEL (?뚮┝?쇳꽣) =====
let _notifTab = 'active';

function toggleAlertPanel() {
  const panel   = document.getElementById('alert-panel');
  const overlay = document.getElementById('alert-panel-overlay');
  const opening = !panel.classList.contains('open');
  panel.classList.toggle('open');
  overlay.classList.toggle('show');
  if (opening) renderAlertPanel();
}

function switchNotifTab(tab, btn) {
  _notifTab = tab;
  document.querySelectorAll('.ap-tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderAlertPanel();
}

function renderAlertPanel() {
  const list = document.getElementById('alert-panel-list');
  if (!list) return;

  const allEvents = state.events.filter(e => !isSwitchPortErrorEvent(e));
  const active    = allEvents.filter(e => e.status === 'active');

  // Update count badge
  const badge = document.getElementById('ap-badge-count');
  if (badge) {
    badge.textContent = active.length;
    badge.className = 'ap-count' + (active.length === 0 ? ' zero' : '');
  }

  const items = _notifTab === 'active' ? active.slice(0, 50) : allEvents.slice(0, 50);

  if (items.length === 0) {
    list.innerHTML = `<div style="text-align:center;color:var(--text-muted);padding:32px 16px;font-size:12px">
      ${_notifTab === 'active' ? '활성 알림이 없습니다' : '알림 내역이 없습니다'}</div>`;
    return;
  }

  list.innerHTML = items.map(a => {
    const hasId = a.id !== undefined && a.id !== null;
    const sevCls = a.severity === 'critical' ? 'critical' : a.severity === 'warning' ? 'medium' : 'info';
    const statCls = a.status === 'resolved' ? 'resolved' : a.status === 'acknowledged' ? 'acknowledged' : a.severity;
    const time = new Date(a.time);
    const timeStr = isNaN(time) ? '' : time.toLocaleString('ko-KR', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' });
    return `<div class="alert-panel-item ${statCls}">
      <div class="ap-item-row">
        <span class="badge ${sevCls}" style="font-size:10px;flex-shrink:0">${a.severity.toUpperCase()}</span>
        <span class="ap-item-msg">${escapeHtml(a.message)}</span>
        ${isAdminUser() && hasId && a.status === 'active'
          ? `<button class="ap-dismiss" onclick="dismissNotification(${a.id})" title="해결 처리">×</button>`
          : ''}
      </div>
      <div class="alert-item-time">${escapeHtml(a.device_name || a.device || '--')} · ${timeStr}</div>
    </div>`;
  }).join('');
}

async function markAllNotificationsRead() {
  const active = state.events.filter(e => e.status === 'active' && e.id != null);
  if (active.length === 0) { showToast('확인할 활성 알림이 없습니다'); return; }
  try {
    await Promise.all(active.map(e => api('/events/ack', 'POST', { event_id: e.id, action: 'acknowledge' })));
    active.forEach(e => { e.status = 'acknowledged'; });
    renderAlertPanel();
    updateBadges();
    updateAlertBanner();
    showToast(`${active.length}건 확인 처리했습니다`);
  } catch (e) {
    showToast('처리 실패: ' + e.message);
  }
}

async function deleteNotifications() {
  const active = state.events.filter(e => e.status === 'active');
  if (active.length === 0 && _notifTab === 'active') {
    showToast('삭제할 활성 알림이 없습니다'); return;
  }
  const count = _notifTab === 'active' ? active.length : state.events.length;
  if (!confirm(`${_notifTab === 'active' ? '활성' : '전체'} 알림 ${count}건을 영구 삭제합니까?`)) return;
  try {
    const qs = _notifTab === 'active' ? '?status=active' : '';
    const res = await api(`/events/bulk${qs}`, 'DELETE');
    await loadAll();
    renderAlertPanel();
    updateAlertBanner();
    showToast(`${res.deleted || 0}건 삭제 완료`);
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

async function dismissNotification(id) {
  try {
    await api('/events/ack', 'POST', { event_id: id, action: 'resolve' });
    const ev = state.events.find(e => e.id === id);
    if (ev) ev.status = 'resolved';
    renderAlertPanel();
    updateBadges();
    updateAlertBanner();
  } catch (e) {
    showToast('처리 실패: ' + e.message);
  }
}

// ===== CHART HELPERS =====
function makeEmptyChart(ctx, label, min = 0, max = 100) {
  return new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [{ label, data: [] }] },
    options: chartOptions(label, min, max)
  });
}

function chartOptions(label, min, max) {
  return {
    responsive: true, maintainAspectRatio: true,
    animation: { duration: 300 },
    plugins: {
      legend: { labels: { color:'#8b949e', font:{size:11}, boxWidth:12 } },
      tooltip: { backgroundColor:'#1c2230', borderColor:'#2a3347', borderWidth:1, titleColor:'#e6edf3', bodyColor:'#8b949e' }
    },
    scales: {
      x: { ticks:{ color:'#4a5568', font:{size:10} }, grid:{ color:'#1e2a3a' } },
      y: { min, max, ticks:{ color:'#4a5568', font:{size:10} }, grid:{ color:'#1e2a3a' } }
    }
  };
}

function destroyChart(key) {
  if (chartInstances[key]) { chartInstances[key].destroy(); delete chartInstances[key]; }
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return isNaN(d) ? '' : d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0');
}

// ===== MISC =====
function setEl(id, text)     { const el = document.getElementById(id); if (el) el.textContent = String(text); }
function setElHtml(id, html) { const el = document.getElementById(id); if (el) el.innerHTML = html; }

function dismissBanner() { const el=document.getElementById('alert-banner'); if(el) el.style.display='none'; }

// ===== AUTH / SESSION =====
function initUserUI() {
  const raw = localStorage.getItem('ng_user');
  if (!raw) return;
  try {
    const u = JSON.parse(raw);
    setEl('sidebar-username', u.full_name || u.username);
    setEl('sidebar-userrole', u.role === 'admin' ? '관리자' : '운영자');
    const av = document.getElementById('sidebar-avatar');
    if (av) av.textContent = (u.full_name || u.username || 'U')[0].toUpperCase();
    if (u.role === 'admin') {
      const navUsers = document.getElementById('nav-item-users');
      if (navUsers) navUsers.style.display = '';
      const clToolbar = document.getElementById('cl-toolbar');
      if (clToolbar) clToolbar.style.display = '';
    } else {
      document.querySelector('.nav-item[data-page="devices"]')?.remove();
    }
  } catch { /* ignore */ }
}

function currentUser() {
  try {
    return JSON.parse(localStorage.getItem('ng_user') || '{}');
  } catch {
    return {};
  }
}

function isAdminUser() {
  return currentUser().role === 'admin';
}

function applyRolePermissions() {
  if (isAdminUser()) return;
  document.querySelector('.nav-item[data-page="devices"]')?.remove();
  if (currentPage === 'devices') navigateTo('dashboard');
  const deviceToolbar = document.querySelector('#page-devices .page-toolbar');
  if (deviceToolbar) deviceToolbar.style.display = 'none';
  document.querySelectorAll('#page-thresholds input, #page-thresholds button').forEach(el => el.disabled = true);
  document.querySelectorAll('#page-alerts input, #page-alerts button').forEach(el => el.disabled = true);
  document.querySelector('.ap-actions .btn-sm:not(.danger)')?.setAttribute('style', 'display:none');
}

function logout() {
  localStorage.removeItem('ng_token');
  localStorage.removeItem('ng_user');
  location.href = '/login';
}

// ===== USERS =====
let editingUserId = null;

async function renderUsers() {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;
  let users;
  try { users = await api('/users'); } catch { return; }
  if (!users || users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px">등록된 사용자 없음</td></tr>';
    return;
  }
  const me = JSON.parse(localStorage.getItem('ng_user') || '{}');
  tbody.innerHTML = users.map(u => `
    <tr>
      <td style="font-weight:600">${u.username}${u.username === me.username ? ' <span class="badge info">나</span>' : ''}</td>
      <td>${u.full_name || '--'}</td>
      <td style="color:var(--text-muted)">${u.email || '--'}</td>
      <td><span class="badge ${u.role === 'admin' ? 'critical' : 'info'}">${u.role === 'admin' ? '관리자' : '운영자'}</span></td>
      <td style="font-size:11px;color:var(--text-muted)">${u.last_login ? new Date(u.last_login).toLocaleString('ko-KR') : '없음'}</td>
      <td><span class="dot ${u.enabled ? 'green' : 'gray'}"></span> ${u.enabled ? '활성' : '비활성'}</td>
      <td>
        <button class="btn-sm" onclick="editUser(${u.id})">수정</button>
        <button class="btn-sm" onclick="changePwModal(${u.id})">비밀번호</button>
        ${u.username !== me.username
          ? `<button class="btn-sm" style="color:var(--red)" onclick="deleteUserById(${u.id},'${u.username}')">삭제</button>`
          : ''}
      </td>
    </tr>`).join('');
}

function showAddUser() {
  editingUserId = null;
  document.getElementById('user-modal-title').textContent = '사용자 추가';
  document.getElementById('um-save-btn').textContent = '추가';
  document.getElementById('um-username').value = '';
  document.getElementById('um-username').disabled = false;
  document.getElementById('um-fullname').value = '';
  document.getElementById('um-email').value = '';
  document.getElementById('um-role').value = 'operator';
  document.getElementById('um-password').value = '';
  document.getElementById('um-pw-group').style.display = '';
  document.getElementById('user-modal').style.display = 'flex';
}

function editUser(id) {
  editingUserId = id;
  api('/users').then(users => {
    const u = users.find(x => x.id === id);
    if (!u) return;
    document.getElementById('user-modal-title').textContent = '사용자 수정';
    document.getElementById('um-save-btn').textContent = '저장';
    document.getElementById('um-username').value = u.username;
    document.getElementById('um-username').disabled = true;
    document.getElementById('um-fullname').value = u.full_name || '';
    document.getElementById('um-email').value = u.email || '';
    document.getElementById('um-role').value = u.role;
    document.getElementById('um-pw-group').style.display = 'none';
    document.getElementById('user-modal').style.display = 'flex';
  });
}

async function saveUser() {
  const username  = document.getElementById('um-username').value.trim();
  const full_name = document.getElementById('um-fullname').value.trim() || null;
  const email     = document.getElementById('um-email').value.trim() || null;
  const role      = document.getElementById('um-role').value;
  const password  = document.getElementById('um-password').value;
  try {
    if (editingUserId === null) {
      if (!username) { showToast('사용자명을 입력하세요'); return; }
      if (password.length < 8) { showToast('비밀번호는 8자 이상이어야 합니다'); return; }
      await api('/users', 'POST', { username, full_name, email, role, password });
      showToast(username + ' 사용자 추가 완료');
    } else {
      await api('/users/' + editingUserId, 'PUT', { full_name, email, role });
      showToast('사용자 정보 수정 완료');
    }
    closeModal('user-modal');
    renderUsers();
  } catch (e) {
    showToast('저장 실패: ' + e.message);
  }
}

async function deleteUserById(id, username) {
  if (!confirm(`"${username}" 사용자를 삭제하시겠습니까?`)) return;
  try {
    await api('/users/' + id, 'DELETE');
    showToast(username + ' 삭제 완료');
    renderUsers();
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}

let pwChangeTargetId = null;

function changePwModal(id) {
  pwChangeTargetId = id;
  document.getElementById('pwc-new').value = '';
  document.getElementById('pwc-confirm').value = '';
  document.getElementById('pwchange-modal').style.display = 'flex';
}

async function savePasswordAdmin() {
  const newPw  = document.getElementById('pwc-new').value;
  const confirm2 = document.getElementById('pwc-confirm').value;
  if (newPw.length < 8) { showToast('비밀번호는 8자 이상이어야 합니다.'); return; }
  if (newPw !== confirm2) { showToast('비밀번호가 일치하지 않습니다.'); return; }
  try {
    await api('/users/' + pwChangeTargetId + '/password', 'PUT', { new_password: newPw });
    showToast('비밀번호 변경 완료');
    closeModal('pwchange-modal');
  } catch (e) {
    showToast('변경 실패: ' + e.message);
  }
}

// ===== CHANGELOG =====
async function renderChangelog() {
  const list = document.getElementById('changelog-list');
  if (!list) return;
  let entries;
  try { entries = await api('/changelog'); } catch { return; }
  if (!entries || entries.length === 0) {
    list.innerHTML = '<div style="color:var(--text-muted);padding:24px">업데이트 내역이 없습니다.</div>';
    return;
  }
  const me = JSON.parse(localStorage.getItem('ng_user') || '{}');
  const isAdmin = me.role === 'admin';
  list.innerHTML = entries.map(e => {
    const changes = Array.isArray(e.changes) ? e.changes : [];
    const date = new Date(e.released_at).toLocaleDateString('ko-KR',
      { year: 'numeric', month: 'long', day: 'numeric' });
    return `
    <div class="chart-card" style="margin-bottom:16px;padding:20px 24px">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="background:#3B82F6;color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:12px;letter-spacing:0.5px">${e.version}</span>
          <span style="font-size:15px;font-weight:600;color:#e6edf3">${e.title}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
          <span style="font-size:11px;color:var(--text-muted)">${date}</span>
          ${isAdmin ? `<button class="btn-sm" style="color:var(--red)" onclick="deleteChangelogEntry(${e.id})">삭제</button>` : ''}
        </div>
      </div>
      ${e.body ? `<div style="margin-top:8px;font-size:12px;color:var(--text-muted)">${e.body}</div>` : ''}
      ${changes.length > 0 ? `
      <ul style="margin-top:12px;padding-left:20px;list-style:disc;display:flex;flex-direction:column;gap:5px">
        ${changes.map(c => `<li style="font-size:13px;color:#8b949e">${c}</li>`).join('')}
      </ul>` : ''}
    </div>`;
  }).join('');
}

function showAddChangelog() {
  document.getElementById('cl-version').value = '';
  document.getElementById('cl-title').value = '';
  document.getElementById('cl-changes').value = '';
  document.getElementById('changelog-modal').style.display = 'flex';
}

async function saveChangelog() {
  const version = document.getElementById('cl-version').value.trim();
  const title   = document.getElementById('cl-title').value.trim();
  const raw     = document.getElementById('cl-changes').value;
  if (!version || !title) { showToast('버전과 제목은 필수입니다'); return; }
  const changes = raw.split('\n').map(l => l.replace(/^[-*]\s*/, '').trim()).filter(Boolean);
  try {
    await api('/changelog', 'POST', { version, title, changes });
    showToast('업데이트 내역을 추가했습니다');
    closeModal('changelog-modal');
    renderChangelog();
  } catch (e) {
    showToast('저장 실패: ' + e.message);
  }
}

async function deleteChangelogEntry(id) {
  if (!confirm('이 업데이트 내역을 삭제하시겠습니까?')) return;
  try {
    await api('/changelog/' + id, 'DELETE');
    showToast('삭제 완료');
    renderChangelog();
  } catch (e) {
    showToast('삭제 실패: ' + e.message);
  }
}
function updateThreshold(id, val, unit = '') {
  const el = document.getElementById(id);
  if (el) el.textContent = `${val}${unit}`;
}
function setOverviewMetric(metric) {
  overviewMetric = metric === 'mem_pct' ? 'mem_pct' : 'cpu_pct';
  document.getElementById('overview-cpu-btn')?.classList.toggle('active', overviewMetric === 'cpu_pct');
  document.getElementById('overview-mem-btn')?.classList.toggle('active', overviewMetric === 'mem_pct');
  renderOverviewChart();
}

function setNetworkMetric(metric) {
  networkMetric = metric === 'net_out_mb' ? 'net_out_mb' : 'net_in_mb';
  document.getElementById('network-in-btn')?.classList.toggle('active', networkMetric === 'net_in_mb');
  document.getElementById('network-out-btn')?.classList.toggle('active', networkMetric === 'net_out_mb');
  renderNetworkChart();
}

function setNetworkTimeRange(range) {
  const hoursByRange = { '1h': 1, '6h': 6, '24h': 24, '7d': 168 };
  networkHours = hoursByRange[range] || 6;
  const select = document.getElementById('network-range-select');
  if (select && select.value !== range) select.value = range;
  renderNetworkChart();
}

async function renderNetworkChart() {
  const ctx = document.getElementById('chart-network');
  if (!ctx) return;
  const runId = ++networkRenderRun;
  const swDevices = state.devices.filter(d => d.type === 'switch');
  const metricKey = networkMetric === 'net_out_mb' ? 'net_out_mb' : 'net_in_mb';
  const metricTitle = metricKey === 'net_out_mb' ? '송신' : '수신';
  const empty = () => {
    if (runId !== networkRenderRun) return;
    destroyChart('network');
    chartInstances['network'] = makeEmptyChart(ctx, 'MB', 0, 100);
  };
  if (swDevices.length === 0) {
    empty();
    return;
  }

  const series = await Promise.all(swDevices.map(async sw => {
    const history = await fetchHistory(sw.id, metricKey, networkHours);
    const ifaces = (getLive(sw)?.metrics?.interfaces || []).filter(i => i.status === 'up');
    const liveValue = ifaces.reduce((sum, iface) => {
      const octets = metricKey === 'net_out_mb' ? iface.out_octets : iface.in_octets;
      return sum + Number(octets || 0);
    }, 0) / 1024 / 1024;
    const now = new Date().toISOString();
    return {
      switch: sw,
      rows: history.length ? history : (liveValue > 0 ? [{ time: now, avg: liveValue }] : [])
    };
  }));

  const { bucketMinutes, points } = buildNetworkTimeline(networkHours);
  if (points.length === 0) {
    empty();
    return;
  }
  const labels = points.map(t => fmtNetworkChartTime(t, networkHours));
  const colors = ['#3B82F6','#22c55e','#f59e0b','#ef4444','#a855f7','#06b6d4','#84cc16','#f97316'];
  const datasets = series
    .map((item, i) => {
      if (item.rows.length === 0) return null;
      const color = colors[i % colors.length];
      const values = bucketNetworkRows(item.rows, bucketMinutes);
      return {
        label: item.switch.name,
        data: points.map(t => values.has(t) ? values.get(t) : null),
        borderColor: color,
        backgroundColor: 'transparent',
        borderWidth: 1.7,
        pointRadius: points.length === 1 ? 3 : 0,
        tension: 0.35,
        spanGaps: true
      };
    })
    .filter(Boolean);
  if (datasets.length === 0) {
    empty();
    return;
  }
  if (runId !== networkRenderRun) return;
  destroyChart('network');
  const options = chartOptions('MB', 0);
  options.scales.x.ticks.maxTicksLimit = networkHours <= 1 ? 7 : 9;
  chartInstances['network'] = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets },
    options
  });
}

function changeTimeRange(value) {
  const hoursByRange = { '1h': 1, '6h': 6, '24h': 24, '7d': 168 };
  overviewHours = hoursByRange[value] || 6;
  renderOverviewChart();
}
const THRESHOLD_BINDINGS = {
  cpu_pct:      { warnInput: 'cpu-warn',  critInput: 'cpu-crit',  warnLabel: 'cpu-warn-val',  critLabel: 'cpu-crit-val',  unit: '%',  direction: 'above' },
  mem_pct:      { warnInput: 'mem-warn',  critInput: 'mem-crit',  warnLabel: 'mem-warn-val',  critLabel: 'mem-crit-val',  unit: '%',  direction: 'above' },
  disk_max_pct: { warnInput: 'disk-warn', critInput: null,        warnLabel: 'disk-warn-val', critLabel: null,            unit: '%',  direction: 'above' },
  temp_c:       { warnInput: 'temp-warn', critInput: 'temp-crit', warnLabel: 'temp-warn-val', critLabel: 'temp-crit-val', unit: '°C', direction: 'above' },
  humidity_pct: { warnInput: 'humi-warn', critInput: null,        warnLabel: 'humi-warn-val', critLabel: null,            unit: '%',  direction: 'above' },
  battery_pct:  { warnInput: 'ups-warn',  critInput: null,        warnLabel: 'ups-warn-val',  critLabel: null,            unit: '%',  direction: 'below' },
};

async function loadThresholds() {
  try {
    const values = await api('/thresholds/effective');
    Object.entries(THRESHOLD_BINDINGS).forEach(([metric, binding]) => {
      const item = values[metric];
      if (!item) return;
      if (binding.warnInput && item.warn_value != null) {
        document.getElementById(binding.warnInput).value = item.warn_value;
        updateThreshold(binding.warnLabel, item.warn_value, binding.unit);
      }
      if (binding.critInput && item.crit_value != null) {
        document.getElementById(binding.critInput).value = item.crit_value;
        updateThreshold(binding.critLabel, item.crit_value, binding.unit);
      }
    });
  } catch (e) {
    console.error('Threshold load failed:', e);
  }
}

async function saveThresholds() {
  try {
    const requests = Object.entries(THRESHOLD_BINDINGS).map(([metric, binding]) => {
      const warnValue = Number(document.getElementById(binding.warnInput)?.value);
      const critValue = binding.critInput
        ? Number(document.getElementById(binding.critInput)?.value)
        : null;
      return api('/thresholds', 'POST', {
        device_id: null,
        metric_name: metric,
        warn_value: Number.isFinite(warnValue) ? warnValue : null,
        crit_value: Number.isFinite(critValue) ? critValue : null,
        direction: binding.direction,
      });
    });
    await Promise.all(requests);
    await loadThresholds();
    showToast('임계값이 저장되었습니다.');
  } catch (e) {
    showToast('임계값 저장 실패: ' + e.message);
  }
}
async function renderAlertConfig() {
  if (alertConfigLoaded) return;
  try {
    const cfg = await api('/alert-config');
    setInputValue('alert-smtp-host', cfg.smtp_host || '');
    setInputValue('alert-smtp-port', cfg.smtp_port || 25);
    setInputValue('alert-smtp-user', cfg.smtp_user || '');
    setInputValue('alert-smtp-password', cfg.smtp_password || '');
    setInputValue('alert-smtp-from', cfg.smtp_from || '');
    setInputValue('alert-emails', (cfg.alert_emails || []).join(', '));
    const smtpStarttls = document.getElementById('alert-smtp-starttls');
    if (smtpStarttls) smtpStarttls.checked = !!cfg.smtp_starttls;
    setInputValue('alert-kakao-rest-key', cfg.kakao_rest_key || '');
    setInputValue('alert-kakao-channel-token', cfg.kakao_channel_token || '');
    const kakaoEnabled = document.getElementById('alert-kakao-enabled');
    if (kakaoEnabled) kakaoEnabled.checked = !!cfg.kakao_enabled;
    alertConfigLoaded = true;
  } catch (e) {
    showToast('알림 설정 조회 실패: ' + e.message);
  }
}

function setInputValue(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = value ?? '';
}

function getAlertConfigPayload() {
  const emails = (document.getElementById('alert-emails')?.value || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
  return {
    smtp_host: document.getElementById('alert-smtp-host')?.value.trim() || '',
    smtp_port: Number(document.getElementById('alert-smtp-port')?.value || 25),
    smtp_user: document.getElementById('alert-smtp-user')?.value.trim() || '',
    smtp_password: document.getElementById('alert-smtp-password')?.value || '',
    smtp_from: document.getElementById('alert-smtp-from')?.value.trim() || '',
    smtp_starttls: !!document.getElementById('alert-smtp-starttls')?.checked,
    alert_emails: emails,
    kakao_enabled: !!document.getElementById('alert-kakao-enabled')?.checked,
    kakao_rest_key: document.getElementById('alert-kakao-rest-key')?.value.trim() || '',
    kakao_channel_token: document.getElementById('alert-kakao-channel-token')?.value.trim() || ''
  };
}

async function saveAlertConfig() {
  try {
    showToast('알림 설정 저장 중...');
    const payload = getAlertConfigPayload();
    const res = await api('/alert-config', 'POST', payload);
    alertConfigLoaded = false;
    if (res.persisted === false) {
      showToast('알림 설정은 즉시 반영됐지만 파일 저장은 실패했습니다. config.yaml 권한을 확인하세요.');
    } else {
      showToast('알림 설정이 시스템에 반영되었습니다.');
    }
    return true;
  } catch (e) {
    showToast('알림 설정 저장 실패: ' + e.message);
    return false;
  }
}

async function testEmail() {
  try {
    if (!isAdminUser()) {
      showToast('테스트 메일 발송은 관리자 권한이 필요합니다.');
      return;
    }
    showToast('테스트 이메일 발송 요청 중...');
    const saved = await saveAlertConfig();
    if (!saved) return;
    const firstRecipient = (document.getElementById('alert-emails')?.value || '').split(',').map(v => v.trim()).find(Boolean);
    await api('/alert-config/test-email', 'POST', { recipient: firstRecipient || null });
    showToast('테스트 이메일 발송 완료');
  } catch (e) {
    showToast('테스트 이메일 실패: ' + e.message);
  }
}

async function testKakao() {
  try {
    if (!isAdminUser()) {
      showToast('카카오톡 설정 저장은 관리자 권한이 필요합니다.');
      return;
    }
    const saved = await saveAlertConfig();
    if (!saved) return;
    showToast('카카오톡 설정이 저장되었습니다. 실제 발송은 이벤트 발생 시 수행됩니다.');
  } catch (e) {
    showToast('카카오톡 설정 저장 실패: ' + e.message);
  }
}
window.renderAlertConfig = renderAlertConfig;
window.saveAlertConfig = saveAlertConfig;
window.testEmail = testEmail;
window.testKakao = testKakao;
function updateNVD()       { showToast('오프라인 환경은 scripts/download_nvd.py로 파일을 생성한 뒤 반입하세요.'); }

// Previous CVE table renderer kept for reference during migration.
function renderCVETableDeprecated() {
  const tbody = document.getElementById('cve-tbody');
  if (!tbody) return;
  const items = state.cves.items || [];
  if (items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">?쒖떆??CVE ?곗씠???놁쓬</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(c => `
    <tr>
      <td style="font-family:var(--mono);font-weight:600;color:var(--accent)">${c.cve_id}</td>
      <td><span class="badge ${c.severity.toLowerCase()}">${c.severity}</span></td>
      <td style="font-weight:700;color:${c.cvss>=9?'var(--red)':c.cvss>=7?'var(--orange)':'var(--yellow)'}">${c.cvss.toFixed(1)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${c.cwe || '--'}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.description}">${c.description}</td>
      <td>${(c.affected_devices || [c.device]).map(d => `<span class="badge info" style="margin-right:2px">${d}</span>`).join('')}</td>
      <td><span class="badge medium">誘몄셿猷?/span></td>
      <td style="white-space:nowrap">
        <button class="btn-sm" onclick="showCVEDetail('${c.cve_id}')">상세</button>
        <button class="btn-sm" onclick="completeCVE('${c.cve_id}')">?꾨즺</button>
      </td>
    </tr>`).join('');
}

async function completeCVE(id) {
  try {
    await api('/security/cves/' + encodeURIComponent(id) + '/complete', 'POST');
    await loadCVEs();
    renderSecurity();
    showToast(`${id} 완료 처리`);
  } catch (e) {
    showToast('CVE 완료 처리 실패');
    console.error(e);
  }
}

async function renderDevices() {
  const tbody = document.getElementById('devices-tbody');
  if (!tbody) return;
  if (state.devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">등록된 장비 없음</td></tr>';
    return;
  }
  tbody.innerHTML = state.devices.map(d => {
    const st = deviceStatus(d);
    const dot = st === 'critical' ? 'red' : st === 'warning' ? 'yellow' : st === 'offline' ? 'gray' : 'green';
    const osText = escapeHtml(d.os_version || '--');
    return `<tr>
      <td style="font-weight:600">${escapeHtml(d.name)}</td>
      <td>${TYPE_KO[d.type] || escapeHtml(d.type)}</td>
      <td style="font-family:var(--mono)">${escapeHtml(d.ip_address)}</td>
      <td><span class="badge info">${escapeHtml(d.snmp_version || 'v2c')}</span></td>
      <td style="font-family:var(--mono);color:var(--text-muted)">${escapeHtml(d.community || '--')}</td>
      <td class="device-os-cell" title="${osText}">${osText}</td>
      <td><span class="status-inline"><span class="dot ${dot}"></span>${statusLabel(st)}</span></td>
      <td>${isAdminUser()
        ? `<div class="table-actions">
             <button class="btn-sm" onclick="editDevice(${d.id})">수정</button>
             <button class="btn-sm danger" onclick="deleteDevice(${d.id})">삭제</button>
           </div>`
        : '<span class="readonly-label">조회 전용</span>'}</td>
    </tr>`;
  }).join('');
}

async function renderEvents(filter) {
  if (filter !== undefined) _eventSevFilter = filter;
  const tbody = document.getElementById('events-tbody');
  if (!tbody) return;

  const searchVal = (document.getElementById('event-search')?.value || '').toLowerCase();
  const dateFrom = document.getElementById('event-date-from')?.value;
  const dateTo = document.getElementById('event-date-to')?.value;
  let list = _eventSevFilter === 'all'
    ? state.events.filter(e => !isSwitchPortErrorEvent(e))
    : state.events.filter(e => e.severity === _eventSevFilter && !isSwitchPortErrorEvent(e));
  if (searchVal) {
    list = list.filter(e =>
      (e.message || '').toLowerCase().includes(searchVal) ||
      (e.device_name || '').toLowerCase().includes(searchVal) ||
      (e.category || '').toLowerCase().includes(searchVal)
    );
  }
  if (dateFrom) list = list.filter(e => new Date(e.time) >= new Date(dateFrom));
  if (dateTo) list = list.filter(e => new Date(e.time) <= new Date(dateTo + 'T23:59:59'));
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px">이벤트 없음</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(e => {
    const hasId = e.id !== undefined && e.id !== null;
    const devName = e.device_name || e.device || '--';
    const sevCls = e.severity === 'critical' ? 'critical' : e.severity === 'warning' ? 'medium' : 'info';
    const stCls = e.status === 'active' ? 'critical' : e.status === 'acknowledged' ? 'medium' : 'ok';
    const stLabel = e.status === 'active' ? '활성' : e.status === 'acknowledged' ? '확인됨' : '해결됨';
    const adminActions = isAdminUser() && hasId
      ? `<button class="btn-sm" onclick="ackEvent(${e.id},'acknowledge')" ${e.status !== 'active' ? 'disabled style="opacity:0.4"' : ''}>확인</button>
         <button class="btn-sm" onclick="ackEvent(${e.id},'resolve')" ${e.status === 'resolved' ? 'disabled style="opacity:0.4"' : ''}>해결</button>`
      : '';
    const deleteAction = hasId
      ? `<button class="btn-sm" style="color:var(--red)" onclick="deleteEvent(${e.id})">삭제</button>`
      : '<span style="color:var(--text-muted);font-size:11px">대기중</span>';
    return `<tr>
      <td style="font-family:var(--mono);white-space:nowrap;font-size:11px">${new Date(e.time).toLocaleString('ko-KR')}</td>
      <td><span class="badge ${sevCls}">${e.severity.toUpperCase()}</span></td>
      <td style="font-weight:600">${devName}</td>
      <td style="color:var(--text-muted)">${e.category || '--'}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.message}">${e.message}</td>
      <td><span class="badge ${stCls}">${stLabel}</span></td>
      <td style="white-space:nowrap">${adminActions}${deleteAction}</td>
    </tr>`;
  }).join('');
}

function renderAffectedChart() {
  const ctx = document.getElementById('affected-chart');
  if (!ctx) return;
  destroyChart('affected');
  const cnt = {};
  (state.cves.items || []).forEach(c => {
    (c.affected_devices || [c.device]).forEach(d => {
      cnt[d] = (cnt[d] || 0) + 1;
    });
  });
  const devs = Object.entries(cnt).sort((a, b) => b[1] - a[1]);
  if (devs.length === 0) {
    chartInstances['affected'] = makeEmptyChart(ctx, '영향 장비');
    return;
  }
  chartInstances['affected'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: devs.map(d => d[0]),
      datasets: [{
        data: devs.map(d => d[1]),
        backgroundColor: ['#3B82F6','#22c55e','#f59e0b','#ef4444','#a855f7','#06b6d4'],
        borderRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 35, minRotation: 0 },
          grid: { color: '#1e2a3a' }
        },
        y: {
          ticks: { color: '#8b949e', font: { size: 10 } },
          grid: { color: '#1e2a3a' },
          stepSize: 1
        }
      }
    }
  });
}

// Final CVE table renderer. Keep action labels explicit for operators.
function renderCVETable() {
  const tbody = document.getElementById('cve-tbody');
  if (!tbody) return;
  const items = state.cves.items || [];
  if (items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px">표시할 CVE 데이터 없음</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(c => `
    <tr>
      <td style="font-family:var(--mono);font-weight:600;color:var(--accent)">${c.cve_id}</td>
      <td><span class="badge ${c.severity.toLowerCase()}">${c.severity}</span></td>
      <td style="font-weight:700;color:${c.cvss>=9?'var(--red)':c.cvss>=7?'var(--orange)':'var(--yellow)'}">${c.cvss.toFixed(1)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${c.cwe || '--'}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.description}">${c.description}</td>
      <td>${(c.affected_devices || [c.device]).map(d => `<span class="badge info" style="margin-right:2px">${d}</span>`).join('')}</td>
      <td><span class="badge medium">패치 대기</span></td>
      <td style="white-space:nowrap">
        <button class="btn-sm" onclick="showCVEDetail('${c.cve_id}')">상세</button>
        ${isAdminUser() ? `<button class="btn-sm" onclick="completeCVE('${c.cve_id}')">패치 완료</button>` : ''}
      </td>
    </tr>`).join('');
}
function showAddProcess()  { showToast('프로세스는 SNMP hrSWRun OID 지원 장비에서 자동 수집됩니다.'); }

window.setOverviewMetric = setOverviewMetric;
window.setNetworkMetric = setNetworkMetric;
window.setNetworkTimeRange = setNetworkTimeRange;
window.resetSwitchErrorCounters = resetSwitchErrorCounters;
window.changeTimeRange = changeTimeRange;
window.updateSnmpV3Fields = updateSnmpV3Fields;

async function showCVEDetail(id) {
  try {
    const c = await api('/security/cves/' + encodeURIComponent(id));
    document.getElementById('cve-detail-title').textContent = `${c.cve_id || c.id} 상세`;
    document.getElementById('cve-detail-id').textContent = c.cve_id || c.id || '--';
    document.getElementById('cve-detail-severity').textContent = c.severity || '--';
    document.getElementById('cve-detail-score').textContent =
      c.cvss != null ? Number(c.cvss).toFixed(1) : c.score != null ? Number(c.score).toFixed(1) : '--';
    document.getElementById('cve-detail-cwe').textContent = c.cwe || '--';
    document.getElementById('cve-detail-published').textContent = c.published || '--';
    document.getElementById('cve-detail-vector').textContent = c.vector || '--';
    document.getElementById('cve-detail-description').textContent =
      c.description || c.desc || '상세 설명이 없습니다.';
    const modal = document.getElementById('cve-detail-modal');
    if (modal.parentElement !== document.body) {
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
  } catch (e) {
    showToast(id + ' 상세 정보를 불러올 수 없습니다.');
  }
}

function showToast(msg) {
  const t = document.createElement('div');
  t.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#1c2230;border:1px solid #2a3347;color:#e6edf3;padding:10px 16px;border-radius:8px;font-size:12px;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.4);max-width:360px;';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

