'use strict';

window.SoftwareInventory = (() => {
  const fields = { server_name: '서버명', ip_address: 'IP', software_name: '소프트웨어 이름', software_version: '소프트웨어 버전' };
  const ops = { contains: '포함', equals: '일치', not_contains: '제외', starts_with: '시작 문자', is_empty: '값 없음' };
  const sources = { registry: '설치 레지스트리', rpm: 'RPM 패키지', dpkg: 'DEB 패키지', process: '실행 프로세스', tomcat: 'Tomcat 메타데이터', configured: '직접 등록 정보' };
  const defaults = () => ({ filters: [], os_family: '', source: '', freshness: 'all', sort: 'server_name', direction: 'asc', page: 1, page_size: 50 });
  let query = defaults(), initialized = false, result = null, coverage = null, sequence = 0, lastQuery = '', lastTime = 0, pending = false, saved = [];
  const el = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
  const icon = name => `<i data-lucide="${name}" aria-hidden="true"></i>`;
  const icons = () => window.lucide?.createIcons();
  const num = value => Number(value || 0).toLocaleString('ko-KR');
  const date = value => value ? new Date(value).toLocaleString('ko-KR') : '미수집';
  const key = () => `ng_software_search:${currentUser().username || 'user'}`;
  function error(message = '') { el('si-error').textContent = message; el('si-error').hidden = !message; }
  function validQuery(value) {
    return value && Array.isArray(value.filters) && value.filters.length <= 20 && value.filters.every(f => fields[f.field] && ops[f.op] && typeof f.value === 'string' && f.value.length <= 200);
  }
  function sync() {
    for (const [id, property] of Object.entries({ 'si-os': 'os_family', 'si-source': 'source', 'si-freshness': 'freshness', 'si-size': 'page_size' })) el(id).value = query[property];
    el('si-chips').innerHTML = query.filters.map((f, index) => `<div class="si-chip"><span>${esc(fields[f.field])} · ${esc(ops[f.op])} ${esc(f.value)}</span><button data-remove="${index}" title="조건 삭제" aria-label="${esc(fields[f.field])} 조건 삭제">${icon('x')}</button></div>`).join('');
    document.querySelectorAll('[data-si-sort]').forEach(button => {
      button.parentElement.removeAttribute('aria-sort');
      if (button.dataset.siSort === query.sort) button.parentElement.setAttribute('aria-sort', query.direction === 'asc' ? 'ascending' : 'descending');
    });
    icons();
  }
  function savedOptions() {
    el('si-saved').innerHTML = '<option value="">저장한 검색</option>' + saved.map((entry, index) => `<option value="${index}">${esc(entry.name)}</option>`).join('');
    el('si-delete-saved').disabled = true;
  }
  function init() {
    if (initialized) return;
    initialized = true;
    document.querySelectorAll('.nav-item').forEach(item => { item.title = item.querySelector('.nav-label')?.textContent || ''; });
    try { const cached = JSON.parse(sessionStorage.getItem(key()) || 'null'); if (validQuery(cached)) query = { ...defaults(), ...cached }; } catch (_) {}
    try { saved = JSON.parse(localStorage.getItem(key() + ':saved') || '[]').filter(entry => typeof entry.name === 'string' && validQuery(entry.query)).slice(0, 20); } catch (_) { saved = []; }
    savedOptions(); sync();
    el('si-form').addEventListener('submit', event => {
      event.preventDefault();
      const filter = { field: el('si-field').value, op: el('si-op').value, value: el('si-value').value.trim() };
      if (filter.op === 'is_empty') filter.value = '';
      if (!filter.value && filter.op !== 'is_empty') { el('si-value').focus(); return; }
      if (query.filters.length >= 20) { error('검색 조건은 최대 20개입니다.'); return; }
      if (!query.filters.some(f => JSON.stringify(f) === JSON.stringify(filter))) query.filters.push(filter);
      el('si-value').value = ''; query.page = 1; sync(); search(true);
    });
    el('si-op').addEventListener('change', () => { el('si-value').disabled = el('si-op').value === 'is_empty'; });
    el('si-chips').addEventListener('click', event => { const button = event.target.closest('[data-remove]'); if (button) { query.filters.splice(Number(button.dataset.remove), 1); query.page = 1; sync(); search(true); } });
    el('si-clear').addEventListener('click', () => { query = defaults(); el('si-value').value = ''; el('si-op').value = 'contains'; el('si-value').disabled = false; el('si-saved').value = ''; el('si-delete-saved').disabled = true; sync(); search(true); });
    for (const [id, property] of Object.entries({ 'si-os': 'os_family', 'si-source': 'source', 'si-freshness': 'freshness', 'si-size': 'page_size' })) el(id).addEventListener('change', () => { query[property] = property === 'page_size' ? Number(el(id).value) : el(id).value; query.page = 1; search(true); });
    document.querySelectorAll('[data-si-sort]').forEach(button => button.addEventListener('click', () => { query.direction = query.sort === button.dataset.siSort && query.direction === 'asc' ? 'desc' : 'asc'; query.sort = button.dataset.siSort; query.page = 1; sync(); search(true); }));
    el('si-prev').addEventListener('click', () => { query.page--; search(true); });
    el('si-next').addEventListener('click', () => { query.page++; search(true); });
    el('si-refresh').addEventListener('click', () => { search(true); loadCoverage(); });
    el('si-export').addEventListener('click', exportCsv);
    el('si-close').addEventListener('click', () => el('si-dialog').close());
    el('si-coverage').addEventListener('click', showCoverage);
    el('si-rows').addEventListener('click', async event => {
      const detail = event.target.closest('[data-detail]'), server = event.target.closest('[data-server]');
      if (detail) showDetail(result.items[Number(detail.dataset.detail)]);
      if (server) {
        navigateTo('servers');
        await showServerDetail(Number(server.dataset.server));
        el('server-detail').scrollIntoView({ block: 'start' });
      }
    });
    el('si-save').addEventListener('click', () => { el('si-save-name').value = ''; el('si-save-dialog').showModal(); });
    el('si-save-cancel').addEventListener('click', () => el('si-save-dialog').close());
    el('si-save-form').addEventListener('submit', event => {
      event.preventDefault(); const name = el('si-save-name').value.trim(); if (!name) return;
      const entry = { name, query: JSON.parse(JSON.stringify(query)) }, index = saved.findIndex(s => s.name === name);
      const next = [...saved]; if (index >= 0) next[index] = entry; else next.push(entry);
      if (next.length > 20) { el('si-save-dialog').close(); error('저장한 검색은 최대 20개입니다.'); return; }
      try { localStorage.setItem(key() + ':saved', JSON.stringify(next)); saved = next; savedOptions(); el('si-save-dialog').close(); } catch (_) { el('si-save-dialog').close(); error('브라우저에 검색 조건을 저장하지 못했습니다.'); }
    });
    el('si-saved').addEventListener('change', () => { const value = el('si-saved').value; el('si-delete-saved').disabled = value === ''; if (value !== '') { query = { ...defaults(), ...JSON.parse(JSON.stringify(saved[Number(value)].query)), page: 1 }; sync(); search(true); } });
    el('si-delete-saved').addEventListener('click', () => { const next = saved.filter((_, index) => index !== Number(el('si-saved').value)); try { localStorage.setItem(key() + ':saved', JSON.stringify(next)); saved = next; savedOptions(); } catch (_) { error('저장한 검색을 삭제하지 못했습니다.'); } });
    loadCoverage();
  }
  async function loadCoverage() {
    try { coverage = await api('/software/coverage'); el('si-coverage-label').textContent = `수집 서버 ${num(coverage.reported)} / ${num(coverage.total)}${coverage.attention ? ` · 확인 필요 ${num(coverage.attention)}` : ''}`; }
    catch (_) { coverage = null; el('si-coverage-label').textContent = '수집 현황 조회 실패'; }
  }
  async function search(force = false) {
    const identity = JSON.stringify(query);
    if (!force && identity === lastQuery && (pending || Date.now() - lastTime < 60000)) return;
    const run = ++sequence; lastQuery = identity; pending = true; error();
    el('si-export').disabled = true; el('si-prev').disabled = true; el('si-next').disabled = true;
    el('si-summary').textContent = '조회 중';
    el('si-rows').innerHTML = '<tr><td colspan="4" class="si-state">조회 중</td></tr>';
    const params = new URLSearchParams({ ...query, filters: JSON.stringify(query.filters) });
    try {
      const data = await api('/software?' + params);
      if (run !== sequence) return;
      result = data; query.page = data.page; lastQuery = JSON.stringify(query); lastTime = Date.now();
      try { sessionStorage.setItem(key(), JSON.stringify(query)); } catch (_) {}
      el('si-summary').innerHTML = `<strong>${num(data.total)}</strong>건 · 서버 <strong>${num(data.servers)}</strong>대 · 소프트웨어 <strong>${num(data.products)}</strong>종`;
      el('si-rows').innerHTML = data.items.length ? data.items.map((row, index) => `<tr><td><button class="si-link" data-server="${Number(row.device_id)}">${esc(row.server_name)}</button></td><td>${esc(row.ip_address)}</td><td><button class="si-link" data-detail="${index}" title="소프트웨어 상세">${esc(row.software_name)}</button></td><td>${row.software_version ? esc(row.software_version) : '<span class="si-unknown">버전 미확인</span>'}</td></tr>`).join('') : '<tr><td colspan="4" class="si-state">검색 결과 없음</td></tr>';
      el('si-page-label').textContent = `${num(data.page)} / ${num(data.pages)} 페이지`;
      el('si-prev').disabled = data.page <= 1; el('si-next').disabled = data.page >= data.pages; el('si-export').disabled = !data.total;
    } catch (err) { if (run === sequence) { result = null; lastTime = 0; error(err.message); el('si-summary').textContent = '조회 실패'; el('si-page-label').textContent = '--'; el('si-rows').innerHTML = '<tr><td colspan="4" class="si-state">데이터를 불러오지 못했습니다.</td></tr>'; } }
    finally { if (run === sequence) pending = false; }
  }
  function dialog(title, html) { el('si-dialog-title').textContent = title; el('si-detail').innerHTML = html; el('si-dialog').showModal(); icons(); }
  function showDetail(row) {
    dialog(row.software_name, `<dl class="si-detail-grid"><dt>서버명</dt><dd>${esc(row.server_name)}</dd><dt>IP</dt><dd>${esc(row.ip_address)}</dd><dt>버전</dt><dd>${esc(row.software_version || '버전 미확인')}</dd><dt>최근 확인</dt><dd>${esc(date(row.last_seen))}</dd></dl>${row.installations.map(item => `<div class="si-installation"><strong>${esc(sources[item.source] || item.source)}</strong><small>경로: ${esc(item.path || '미수집')}</small><small>게시자: ${esc(item.publisher || '미확인')}</small><small>수집: ${esc(date(item.last_seen))}</small></div>`).join('')}`);
  }
  async function showCoverage() {
    await loadCoverage();
    if (!coverage) { error('수집 현황을 불러오지 못했습니다.'); return; }
    dialog('서버별 수집 현황', coverage.items.length ? coverage.items.map(item => {
      const label = !item.collected_at ? '미수집' : item.status === 'failed' ? '수집 실패' : item.status === 'partial' ? '부분 수집' : item.stale ? '24시간 경과' : '수집 완료';
      return `<div class="si-coverage-row"><div><strong>${esc(item.name)}</strong><small>${esc(item.ip_address)} · ${esc(item.os_family || item.snmp_version || '--')}</small><small>${esc(date(item.collected_at))} · Agent ${esc(item.agent_version || '--')}</small>${(item.errors || []).map(message => `<small>${esc(message)}</small>`).join('')}</div><span class="si-coverage-state ${item.stale || item.status !== 'complete' ? 'attention' : ''}">${label}</span></div>`;
    }).join('') : '<p>등록된 서버 없음</p>');
  }
  async function exportCsv() {
    el('si-export').disabled = true; error();
    try {
      const params = new URLSearchParams({ ...query, filters: JSON.stringify(query.filters) });
      const response = await fetch('/api/software/export?' + params, { headers: { Authorization: 'Bearer ' + (localStorage.getItem('ng_token') || '') } });
      if (!response.ok) { if (response.status === 401) { location.href = '/login'; } const body = await response.json(); throw new Error(body.detail || 'CSV 다운로드 실패'); }
      const url = URL.createObjectURL(await response.blob()), link = document.createElement('a');
      link.href = url; link.download = 'netguard-software.csv'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { error(err.message); }
    finally { el('si-export').disabled = pending || !result?.total; }
  }
  document.addEventListener('DOMContentLoaded', () => { if (location.hash === '#processes') navigateTo('processes'); });
  return { render: async () => { init(); await search(); } };
})();
