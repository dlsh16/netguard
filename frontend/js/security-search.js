'use strict';

window.SecuritySearch = (() => {
  const defaults = { q: '', scope: 'affected', view: 'assets', severity: '', device_type: '', asset_id: '', asset_name: '', status: 'open', min_cvss: 0, max_cvss: 10, sort: 'score', page: 1, page_size: 20 };
  let filters = { ...defaults };
  let initialized = false, requestId = 0, detailRequest = 0, result = null, action = null, actionPending = false;
  const charts = {};
  const el = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const icon = name => `<i data-lucide="${name}" aria-hidden="true"></i>`;
  const icons = () => window.lucide?.createIcons();
  const number = value => Number(value || 0).toLocaleString('ko-KR');
  const typeName = type => ({ server: '서버', switch: '스위치', env: '항온항습기', ups: 'UPS', rpi: '라즈베리파이' })[type] || type;
  const typeIcon = type => ({ switch: 'network', ups: 'battery-charging', env: 'thermometer', rpi: 'cpu' })[type] || 'server';
  const level = severity => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity.toLowerCase() : 'none';
  const badge = severity => `<span class="vs-badge ${level(severity)}">${esc(severity === 'NONE' ? '미평가' : severity)}</span>`;
  const score = value => `<span class="vs-score ${value >= 9 ? 'critical' : value >= 7 ? 'high' : value >= 4 ? 'medium' : 'low'}">${Number(value || 0).toFixed(1)}</span>`;
  const date = value => value ? new Date(value).toLocaleDateString('ko-KR') : '--';
  const storageKey = () => `ng_security_search:${currentUser().username || 'user'}`;

  function init() {
    if (initialized) return;
    initialized = true;
    try { filters = { ...defaults, ...JSON.parse(sessionStorage.getItem(storageKey()) || '{}') }; } catch (_) {}
    if (!['assets', 'cves'].includes(filters.view)) filters.view = 'assets';
    if (location.hash === '#security') navigateTo('security');
    el('vs-search-form').addEventListener('submit', event => { event.preventDefault(); filters.q = el('vs-query').value.trim(); search(true); });
    el('vs-refresh').addEventListener('click', () => search());
    el('vs-filter-toggle').addEventListener('click', () => {
      const expanded = document.querySelector('.vs-workspace').classList.toggle('filters-open');
      el('vs-filter-toggle').setAttribute('aria-expanded', String(expanded));
    });
    el('vs-reset').addEventListener('click', () => { filters = { ...defaults }; sync(); search(); });
    const controls = { 'vs-scope': 'scope', 'vs-type': 'device_type', 'vs-status': 'status', 'vs-min': 'min_cvss', 'vs-max': 'max_cvss', 'vs-sort': 'sort', 'vs-page-size': 'page_size' };
    for (const [id, key] of Object.entries(controls)) el(id).addEventListener('change', () => {
      filters[key] = el(id).value;
      if (key === 'scope' && filters.scope === 'catalog') filters.view = 'cves';
      sync(); search(true);
    });
    document.querySelectorAll('.vs-severities input').forEach(input => input.addEventListener('change', () => {
      filters.severity = [...document.querySelectorAll('.vs-severities input:checked')].map(item => item.value).join(',');
      search(true);
    }));
    document.querySelectorAll('.vs-tabs button').forEach(button => button.addEventListener('click', () => {
      filters.view = button.dataset.view;
      if (filters.view === 'assets') filters.scope = 'affected';
      if (filters.view === 'assets' && ['newest', 'id'].includes(filters.sort) || filters.view === 'cves' && filters.sort === 'name') filters.sort = 'score';
      sync(); search(true);
    }));
    el('vs-prev').addEventListener('click', () => { filters.page = Math.max(1, filters.page - 1); search(); });
    el('vs-next').addEventListener('click', () => { filters.page = Math.min(result?.pages || 1, filters.page + 1); search(); });
    el('vs-distribution-toggle').addEventListener('click', () => {
      el('vs-distributions').hidden = !el('vs-distributions').hidden;
      el('vs-distribution-toggle').setAttribute('aria-expanded', String(!el('vs-distributions').hidden));
      if (!el('vs-distributions').hidden && result) renderCharts();
    });
    el('vs-result-list').addEventListener('click', handleResultAction);
    el('vs-active-asset').addEventListener('click', () => { filters.asset_id = ''; filters.asset_name = ''; sync(); search(true); });
    el('vs-detail-close').addEventListener('click', () => el('vs-detail-dialog').close());
    el('vs-detail-dialog').addEventListener('close', () => { detailRequest++; });
    el('vs-detail-footer').addEventListener('click', handleResultAction);
    el('vs-action-cancel').addEventListener('click', () => el('vs-action-dialog').close());
    el('vs-action-dialog').addEventListener('cancel', event => { if (actionPending) event.preventDefault(); });
    el('vs-action-confirm').addEventListener('click', submitAction);
    sync(); icons();
  }

  function sync() {
    if (filters.view === 'assets' && ['newest', 'id'].includes(filters.sort) || filters.view === 'cves' && filters.sort === 'name') filters.sort = 'score';
    for (const [id, key] of Object.entries({ 'vs-query': 'q', 'vs-scope': 'scope', 'vs-type': 'device_type', 'vs-status': 'status', 'vs-min': 'min_cvss', 'vs-max': 'max_cvss', 'vs-sort': 'sort', 'vs-page-size': 'page_size' })) el(id).value = filters[key];
    document.querySelectorAll('.vs-severities input').forEach(input => { input.checked = filters.severity.split(',').includes(input.value); });
    document.querySelectorAll('.vs-tabs button').forEach(button => button.setAttribute('aria-selected', String(button.dataset.view === filters.view)));
    for (const option of el('vs-sort').options) option.hidden = filters.view === 'assets' ? ['newest', 'id'].includes(option.value) : option.value === 'name';
    el('vs-active-asset').hidden = !filters.asset_id;
    el('vs-active-asset').innerHTML = filters.asset_id ? `<button class="vs-asset-chip" title="자산 필터 해제">${icon('server')}${esc(filters.asset_name)}${icon('x')}</button>` : '';
    icons();
  }

  async function search(resetPage = false) {
    if (resetPage) filters.page = 1;
    const run = ++requestId;
    try { sessionStorage.setItem(storageKey(), JSON.stringify(filters)); } catch (_) {}
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) if (value !== '' && key !== 'asset_name') params.set(key, value);
    el('vs-error').hidden = true;
    el('vs-result-count').textContent = '검색 중...';
    document.querySelector('.vs-results').setAttribute('aria-busy', 'true');
    el('vs-prev').disabled = el('vs-next').disabled = true;
    try {
      const data = await api(`/security/search?${params}`);
      if (run !== requestId) return;
      result = data;
      filters.page = data.page;
      renderResult();
    } catch (error) {
      if (run !== requestId) return;
      result = null;
      el('vs-error').textContent = error.message;
      el('vs-error').hidden = false;
      el('vs-result-count').textContent = '검색 실패';
      el('vs-result-list').innerHTML = '<div class="vs-empty">검색 결과를 불러오지 못했습니다.</div>';
    } finally {
      if (run === requestId) document.querySelector('.vs-results').setAttribute('aria-busy', 'false');
    }
  }

  function renderResult() {
    const d = result;
    for (const [id, value] of Object.entries({ 'vs-total-cves': d.cve_total, 'vs-total-assets': d.asset_total, 'vs-total-critical': d.counts.CRITICAL, 'vs-total-high': d.counts.HIGH, 'vs-catalog-total': d.catalog_total, 'vs-registered': d.registered_assets })) el(id).textContent = number(value);
    document.querySelectorAll('[data-vs-count]').forEach(node => { node.textContent = number(d.counts[node.dataset.vsCount]); });
    el('vs-updated').textContent = `마지막 업데이트 ${d.last_updated ? new Date(d.last_updated).toLocaleString('ko-KR') : '--'}`;
    const warning = d.load_errors?.length ? `NVD 파일 읽기 실패: ${d.load_errors.join(', ')}` : !d.catalog_total ? '로컬 NVD 데이터가 없습니다. NVD 피드 반입 상태를 확인하세요.' : '';
    el('vs-source-warning').textContent = warning;
    el('vs-source-warning').hidden = !warning;
    const start = d.total ? (d.page - 1) * d.page_size + 1 : 0;
    const end = Math.min(d.page * d.page_size, d.total);
    el('vs-result-count').textContent = `${d.view === 'assets' ? '자산' : '취약점'} ${number(d.total)}건 · ${number(start)}–${number(end)}`;
    el('vs-page-label').textContent = `${d.page} / ${d.pages}`;
    el('vs-prev').disabled = d.page <= 1;
    el('vs-next').disabled = d.page >= d.pages;
    if (!d.items.length) {
      el('vs-result-list').innerHTML = `<div class="vs-empty">${icon('search-x')}<strong>${d.catalog_total ? '검색 결과가 없습니다.' : 'NVD 데이터 없음'}</strong><span>${d.catalog_total ? '현재 조건과 일치하는 항목이 없습니다.' : '반입된 NVD 피드를 찾을 수 없습니다.'}</span></div>`;
    } else if (d.view === 'assets') {
      el('vs-result-list').innerHTML = `<div class="vs-table-scroll"><table class="vs-table vs-asset-table"><thead><tr><th>자산 / IP 주소</th><th>유형 · OS / 제품</th><th>최고 CVSS</th><th>심각도 분포</th><th>CVE 후보</th><th><span class="vs-sr-only">액션</span></th></tr></thead><tbody>${d.items.map(assetRow).join('')}</tbody></table></div>`;
    } else {
      el('vs-result-list').innerHTML = `<div class="vs-table-scroll"><table class="vs-table vs-cve-table"><thead><tr><th>CVE / 공개일</th><th>심각도 / 점수</th><th>제품 · 설명</th><th>영향 후보 자산</th><th>조치</th><th>액션</th></tr></thead><tbody>${d.items.map(cveRow).join('')}</tbody></table></div>`;
    }
    if (!el('vs-distributions').hidden) renderCharts();
    icons();
  }

  function assetRow(a) {
    const bars = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].filter(s => a.counts[s]).map(s => `<span class="${level(s)}" style="flex:${Number(a.counts[s])}" title="${s}: ${number(a.counts[s])}"></span>`).join('');
    return `<tr><td><div class="vs-asset-identity">${icon(typeIcon(a.type))}<div><button class="vs-link" data-action="asset" data-id="${esc(a.id)}" data-name="${esc(a.name)}">${esc(a.name)}</button><span class="vs-mono">${esc(a.ip_address)}</span></div></div></td><td><span class="vs-secondary">${esc(typeName(a.type))}</span><div class="vs-os" title="${esc(a.os_version)}">${esc(a.os_version || 'OS 정보 없음')}</div></td><td>${score(a.max_cvss)}</td><td><div class="vs-severity-bar">${bars}</div><div class="vs-bar-label">Critical ${number(a.counts.CRITICAL)} · High ${number(a.counts.HIGH)}</div></td><td><strong>${number(a.cve_count)}</strong></td><td><button class="vs-icon-button" data-action="asset" data-id="${esc(a.id)}" data-name="${esc(a.name)}" title="취약점 보기" aria-label="${esc(a.name)} 취약점 보기">${icon('arrow-right')}</button></td></tr>`;
  }

  function cveRow(c) {
    const affected = c.affected_assets || [];
    return `<tr><td><button class="vs-link vs-mono" data-action="detail" data-id="${esc(c.cve_id)}">${esc(c.cve_id)}</button><div class="vs-secondary">${esc(date(c.published))}</div></td><td>${badge(c.severity)}<div class="vs-cve-score">CVSS <strong>${Number(c.cvss).toFixed(1)}</strong></div></td><td><div class="vs-products">${esc(c.products.join(', ').replaceAll('_', ' ') || c.cwe || '제품 정보 없음')}</div><div class="vs-description" title="${esc(c.description)}">${esc(c.description)}</div><span class="vs-secondary">${esc(c.cwes.join(' · '))}</span></td><td>${affected.slice(0, 2).map(a => `<div class="vs-target"><span>${esc(a.name)}</span><span class="vs-mono">${esc(a.ip_address)}</span></div>`).join('')}${affected.length > 2 ? `<span class="vs-secondary">외 ${affected.length - 2}개</span>` : ''}${!affected.length ? '<span class="vs-secondary">연관 자산 없음</span>' : ''}</td><td><span class="vs-status ${c.completed ? 'done' : ''}">${c.completed ? '패치 완료' : '미조치'}</span></td><td><div class="vs-row-actions"><button class="vs-icon-button" title="상세 보고서" aria-label="${esc(c.cve_id)} 상세" data-action="detail" data-id="${esc(c.cve_id)}">${icon('file-search')}</button>${actionButton(c)}</div></td></tr>`;
  }

  function actionButton(c) {
    return isAdminUser() ? `<button class="vs-icon-button" title="${c.completed ? '미조치로 복원' : '패치 완료'}" aria-label="${esc(c.cve_id)} ${c.completed ? '미조치로 복원' : '패치 완료'}" data-action="${c.completed ? 'reopen' : 'complete'}" data-id="${esc(c.cve_id)}">${icon(c.completed ? 'undo-2' : 'check-check')}</button>` : '';
  }

  function handleResultAction(event) {
    const button = event.target.closest('[data-action]');
    if (!button || document.querySelector('.vs-results').getAttribute('aria-busy') === 'true') return;
    if (button.dataset.action === 'asset') {
      filters.asset_id = button.dataset.id; filters.asset_name = button.dataset.name; filters.view = 'cves'; sync(); search(true);
    } else if (button.dataset.action === 'detail') detail(button.dataset.id);
    else confirmAction(button.dataset.id, button.dataset.action === 'reopen');
  }

  function renderCharts() {
    for (const chart of Object.values(charts)) chart.destroy();
    const options = { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#a1a1aa', font: { size: 10 } }, grid: { display: false } }, y: { beginAtZero: true, ticks: { color: '#a1a1aa', precision: 0 }, grid: { color: '#2c2e33' } } } };
    charts.cvss = new Chart(el('vs-cvss-chart'), { type: 'bar', data: { labels: Array.from({ length: 10 }, (_, i) => `${i}–${i + 1}`), datasets: [{ data: result.cvss_bins, backgroundColor: '#d6a345', borderRadius: 2 }] }, options });
    charts.assets = new Chart(el('vs-assets-chart'), { type: 'bar', data: { labels: result.top_assets.map(a => a.name), datasets: [{ data: result.top_assets.map(a => a.cve_count), backgroundColor: '#63b6a2', borderRadius: 2 }] }, options });
  }

  async function detail(id) {
    init();
    const run = ++detailRequest;
    el('vs-detail-title').textContent = id;
    el('vs-detail-body').innerHTML = '<div class="vs-empty">상세 정보를 불러오는 중...</div>';
    el('vs-detail-footer').innerHTML = '';
    if (!el('vs-detail-dialog').open) el('vs-detail-dialog').showModal();
    try {
      const c = await api(`/security/cves/${encodeURIComponent(id)}`);
      if (run !== detailRequest) return;
      const facts = [['심각도', c.severity], ['CVSS', Number(c.cvss).toFixed(1)], ['CWE', c.cwes.join(', ') || '--'], ['공개일', date(c.published)], ['수정일', date(c.modified)], ['조치 상태', c.completed ? '패치 완료' : '미조치']];
      const assets = c.affected_assets || [];
      const urls = (c.references || []).filter(url => { try { return ['https:', 'http:'].includes(new URL(url).protocol); } catch (_) { return false; } });
      el('vs-detail-body').innerHTML = `<dl class="vs-detail-facts">${facts.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><section><h3>취약점 설명</h3><p class="vs-detail-description">${esc(c.description || '설명 없음')}</p></section><section><h3>CVSS 벡터</h3><code>${esc(c.vector || '--')}</code></section><section><h3>영향 후보 자산 <span>${number(assets.length)}</span></h3>${assets.length ? assets.map(a => `<div class="vs-detail-asset"><strong>${esc(a.name)}</strong><span class="vs-mono">${esc(a.ip_address)}</span><span>${esc(a.os_version)}</span><small>${esc(a.match_basis)} · ${esc(a.matched_terms.join(', '))}</small></div>`).join('') : '<p class="vs-secondary">연관된 등록 자산이 없습니다.</p>'}</section><section><h3>영향 제품 / 버전 조건</h3>${c.cpes.length ? c.cpes.map(p => `<div class="vs-cpe"><code>${esc(p.criteria)}</code><span>${esc(Object.entries(p).filter(([key]) => key.startsWith('version') && key !== 'version').map(([key, value]) => `${({ versionStartIncluding: '시작(포함)', versionStartExcluding: '시작(제외)', versionEndIncluding: '종료(포함)', versionEndExcluding: '종료(제외)' })[key]} ${value}`).join(' · '))}</span></div>`).join('') : '<p class="vs-secondary">NVD 제품 조건 미등록</p>'}</section>${urls.length ? `<section><h3>참고 자료</h3><ul class="vs-references">${urls.map(url => `<li><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a></li>`).join('')}</ul></section>` : ''}`;
      el('vs-detail-footer').innerHTML = `<span class="vs-secondary">영향 후보 · 설치 버전 및 적용 조건 확인 필요</span>${actionButton(c)}`;
      icons();
    } catch (error) {
      if (run === detailRequest) el('vs-detail-body').innerHTML = `<p class="vs-error">${esc(error.message)}</p>`;
    }
  }

  function confirmAction(id, completed) {
    if (!isAdminUser()) return;
    init(); action = { id, completed };
    el('vs-action-title').textContent = completed ? '미조치로 복원' : '패치 완료 처리';
    el('vs-action-message').textContent = `${id}의 전체 등록 자산에 대한 조치 상태를 ${completed ? '미조치로 복원' : '패치 완료로 변경'}하시겠습니까?`;
    el('vs-action-error').textContent = '';
    el('vs-action-confirm').disabled = false;
    el('vs-action-confirm').textContent = completed ? '복원' : '패치 완료';
    el('vs-action-dialog').showModal();
  }

  async function submitAction() {
    if (!action || actionPending) return;
    const target = { ...action };
    actionPending = true;
    el('vs-action-confirm').disabled = el('vs-action-cancel').disabled = true;
    try {
      await api(`/security/cves/${encodeURIComponent(target.id)}/complete`, target.completed ? 'DELETE' : 'POST');
      el('vs-action-dialog').close();
      if (el('vs-detail-dialog').open) el('vs-detail-dialog').close();
      await Promise.all([search(), loadCVEs()]);
      showToast(`${target.id} ${target.completed ? '미조치로 복원되었습니다.' : '패치 완료 처리되었습니다.'}`);
    } catch (error) { el('vs-action-error').textContent = error.message; }
    finally { actionPending = false; el('vs-action-confirm').disabled = el('vs-action-cancel').disabled = false; }
  }

  document.addEventListener('DOMContentLoaded', () => { init(); });
  return { render: async () => { init(); await search(); }, detail, confirmAction };
})();
