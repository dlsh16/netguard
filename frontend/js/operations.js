/* RSS advisories, outbound agent checks and asset exports. No remote assets. */
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => escapeHtml(String(value ?? ''));
  const date = value => value ? new Date(value).toLocaleString('ko-KR') : '--';
  const statusNames = {queued:'대기',running:'실행 중',completed:'완료',failed:'실패',expired:'대기 만료',unknown:'결과 미확인',cancelled:'취소'};
  let advisoryPage=1, jobPage=1, nvd=false, lastAdvisory=0, lastChecks=0, busyChecks=false, advisoryRequest=0;
  const icons=()=>window.lucide?.createIcons();
  document.querySelectorAll('[data-page]').forEach(link=>link.addEventListener('click',()=>$('sidebar').classList.remove('mobile-open')));
  function error(id, value='') { $(id).textContent=value; $(id).hidden=!value; }
  async function advisories(force=false) {
    if (!force && Date.now()-lastAdvisory<15000) return;
    const request=++advisoryRequest;
    document.querySelectorAll('[data-ops-admin]').forEach(el=>el.hidden=!isAdminUser());
    try {
      const data=await api(`/security/advisories?q=${encodeURIComponent($('ops-advisory-query').value)}&page=${advisoryPage}`);
      if(request!==advisoryRequest)return;
      lastAdvisory=Date.now(); error('ops-advisory-error',data.sync?.error || '');
      $('ops-sync-status').textContent=`마지막 수신: ${date(data.sync?.succeeded_at)} · ${data.automatic ? `자동 ${Math.round(data.interval_seconds/60)}분` : '수동 / 파일 반입'}`;
      $('ops-advisory-list').innerHTML=data.items.map(item=>`<article class="ops-advisory"><time>${date(item.published_at)}</time><h2><a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">${esc(item.title)}</a></h2><p>${esc(item.summary || '본문은 공식 공지에서 확인하세요.')}</p><details ${item.match_count?'open':''}><summary>영향 후보 ${item.match_count}건 · 제품·버전 확인 필요</summary>${item.match_count?`<div class="ops-table-scroll"><table class="data-table"><thead><tr><th>서버명</th><th>IP</th><th>소프트웨어 / OS</th><th>버전</th><th>판단 근거</th><th>정보 수신</th></tr></thead><tbody>${item.matches.map(m=>`<tr><td>${esc(m.server_name)}</td><td>${esc(m.ip_address)}</td><td>${esc(m.software_name)}</td><td>${esc(m.software_version||'미확인')}</td><td>${esc(m.reason)}</td><td>${date(m.inventory_at)}</td></tr>`).join('')}</tbody></table></div>${item.match_count>200?'<p>상위 200건 표시</p>':''}`:'<p>수집된 자산 정보에서 일치 후보가 없습니다. 미수집 소프트웨어는 판정 대상에서 제외됩니다.</p>'}</details></article>`).join('') || '<p class="ops-note">수신된 보안공지가 없습니다.</p>';
      $('ops-advisory-page').textContent=`${advisoryPage} / ${Math.max(1,Math.ceil(data.total/20))} · ${data.total}건`;
      $('ops-advisory-prev').disabled=advisoryPage<=1; $('ops-advisory-next').disabled=advisoryPage*20>=data.total;
    }catch(e){error('ops-advisory-error',e.message);}
  }
  async function security(){ if(nvd)await window.SecuritySearch.render(); else await advisories(); }
  async function selectSecurity(value){nvd=value;$('ops-nvd').hidden=!value;$('ops-advisories').hidden=value;$('ops-nvd-tab').setAttribute('aria-selected',String(value));$('ops-advisory-tab').setAttribute('aria-selected',String(!value));await security();}
  async function jobs(){
    const params=new URLSearchParams({page:jobPage});
    if($('ops-check-device').value)params.set('device_id',$('ops-check-device').value);
    const from=$('ops-check-from').value,to=$('ops-check-to').value;
    if(from)params.set('since',new Date(from+'T00:00:00').toISOString());
    if(to){const end=new Date(to+'T00:00:00');end.setDate(end.getDate()+1);params.set('until',end.toISOString());}
    const data=await api('/security/checks/jobs?'+params);
    $('ops-check-jobs').innerHTML=data.items.map(j=>`<tr><td>${esc(j.name)}<br>${esc(j.ip_address)}</td><td>${j.run_type==='security'?'취약점 점검':'정기 점검'}</td><td>${date(j.requested_at)}</td><td>${date(j.started_at)}</td><td>${date(j.completed_at)}</td><td>${esc(statusNames[j.status]||j.status)} ${j.run_id?`<button class="btn-sm" data-run="${j.run_id}">결과</button>`:''}${j.status==='queued'&&isAdminUser()?`<button class="btn-sm" data-cancel="${j.id}">취소</button>`:''}<div>${esc(j.detail)}</div></td></tr>`).join('') || '<tr><td colspan="6">조회 기간에 실행 이력이 없습니다.</td></tr>';
    $('ops-job-page').textContent=`${jobPage} 페이지`;$('ops-job-prev').disabled=jobPage===1;$('ops-job-next').disabled=!data.has_more;
  }
  async function checks(force=false){
    if(busyChecks||(!force&&Date.now()-lastChecks<15000))return;
    busyChecks=true;
    try{
      const rows=await api('/security/checks/agents');
      const selected=$('ops-check-device').value;
      $('ops-check-device').innerHTML='<option value="">전체 서버</option>'+rows.map(d=>`<option value="${d.id}">${esc(d.name)}</option>`).join('');
      $('ops-check-device').value=selected;
      $('ops-check-servers').innerHTML=rows.map(d=>{
        const online=d.last_seen&&Date.now()-new Date(d.last_seen).getTime()<300000;
        const active=['queued','running'].includes(d.status);
        return `<tr><td>${esc(d.name)}</td><td>${esc(d.ip_address)}</td><td>${d.snmp_version!=='agent'?'Agent 미설치':online?'연결됨':d.enrolled?'연결 대기':'연결키 미등록'}<br>${date(d.last_seen)}</td><td>${esc(statusNames[d.status]||'--')}</td><td><div class="ops-actions">${isAdminUser()&&d.snmp_version==='agent'?`<button class="btn-sm" data-check="security" data-device="${d.id}" ${!online||active?'disabled':''}><i data-lucide="shield-check"></i>취약점 점검</button><button class="btn-sm" data-check="maintenance" data-device="${d.id}" ${!online||active?'disabled':''}><i data-lucide="clipboard-check"></i>정기 점검</button><button class="btn-sm" data-enroll="${d.id}" ${active?'disabled':''} title="서버별 연결키 발급"><i data-lucide="key-round"></i>연결키</button>`:'--'}</div></td></tr>`;
      }).join('')||'<tr><td colspan="5">등록 서버가 없습니다.</td></tr>';
      await jobs();lastChecks=Date.now();error('ops-check-error');icons();
    }catch(e){error('ops-check-error',e.message);}finally{busyChecks=false;}
  }
  $('ops-advisory-tab').onclick=()=>selectSecurity(false);$('ops-nvd-tab').onclick=()=>selectSecurity(true);
  $('ops-advisory-form').onsubmit=e=>{e.preventDefault();advisoryPage=1;advisories(true);};
  $('ops-advisory-prev').onclick=()=>{advisoryPage--;advisories(true);};$('ops-advisory-next').onclick=()=>{advisoryPage++;advisories(true);};
  $('ops-sync').onclick=async e=>{e.currentTarget.disabled=true;try{await api('/security/advisories/sync','POST');await advisories(true);}catch(err){error('ops-advisory-error',err.message);}finally{$('ops-sync').disabled=false;}};
  $('ops-rss-file').onchange=async e=>{
    const file=e.target.files[0];if(!file)return;
    try{if(file.size>5242880)throw new Error('RSS 파일은 5 MiB 이하여야 합니다.');const body=new FormData();body.append('file',file);const r=await fetch('/api/security/advisories/import',{method:'POST',headers:{Authorization:'Bearer '+localStorage.getItem('ng_token')},body});if(!r.ok)throw new Error((await r.json()).detail||'반입 실패');advisoryPage=1;await advisories(true);}catch(err){error('ops-advisory-error',err.message);}finally{e.target.value='';}
  };
  $('ops-check-refresh').onclick=()=>checks(true);
  $('ops-check-filter').onsubmit=e=>{e.preventDefault();jobPage=1;jobs().catch(e=>error('ops-check-error',e.message));};
  $('ops-job-prev').onclick=()=>{jobPage--;jobs().catch(e=>error('ops-check-error',e.message));};$('ops-job-next').onclick=()=>{jobPage++;jobs().catch(e=>error('ops-check-error',e.message));};
  $('ops-token-close').onclick=()=>{$('ops-token-value').textContent='';$('ops-token-dialog').close();};
  $('ops-token-dialog').addEventListener('close',()=>{$('ops-token-value').textContent='';});
  $('page-security-checks').addEventListener('click',async e=>{
    const button=e.target.closest('button');if(!button)return;
    try{
      if(button.dataset.run){await showCheckRunResults(Number(button.dataset.run),'원격 점검');$('check-detail-title').scrollIntoView({block:'start',behavior:'smooth'});return;}
      if(button.dataset.check){if(!confirm('이 서버에서 '+(button.dataset.check==='security'?'취약점 점검':'정기 점검')+'을 실행하시겠습니까? 점검 중 CPU/디스크 부하가 발생할 수 있습니다.'))return;button.disabled=true;await api(`/security/checks/agents/${button.dataset.device}/jobs`,'POST',{run_type:button.dataset.check});await checks(true);}
      if(button.dataset.enroll){if(!confirm('새 연결키를 발급하면 기존 연결키는 폐기됩니다. 계속하시겠습니까?'))return;button.disabled=true;const cfg=await api(`/security/checks/agents/${button.dataset.enroll}/enroll`,'POST');$('ops-token-value').textContent=JSON.stringify(cfg,null,2);$('ops-token-dialog').showModal();await checks(true);}
      if(button.dataset.cancel){button.disabled=true;await api(`/security/checks/jobs/${button.dataset.cancel}/cancel`,'POST');await checks(true);}
    }catch(err){button.disabled=false;error('ops-check-error',err.message);}
  });
  $('ops-export-assets').onclick=async e=>{const btn=e.currentTarget;btn.disabled=true;try{const r=await fetch('/api/assets/export.xlsx',{headers:{Authorization:'Bearer '+localStorage.getItem('ng_token')}});if(!r.ok)throw new Error('엑셀 다운로드 실패: '+r.status);const url=URL.createObjectURL(await r.blob());const a=document.createElement('a');a.href=url;a.download='NetGuard-정보자산목록.xlsx';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(err){showToast(err.message);}finally{btn.disabled=false;}};
  setInterval(()=>{if(document.hidden)return;if($('page-security-checks').classList.contains('active'))checks(true);if($('page-security').classList.contains('active')&&!nvd)advisories(true);},30000);
  window.NetGuardOperations={security,checks};icons();
})();
