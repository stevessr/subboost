'use strict';
const el = (id) => document.getElementById(id);
let admin = sessionStorage.getItem('subboost-rs-admin') || '';
let profiles = [], current = null, savedTemplates = [];
function notice(message, bad = false) {
  const box = el('notice');
  box.textContent = String(message);
  box.classList.remove('hidden');
  box.classList.toggle('bad',bad);
}
function link(profile, target) {
  return location.origin + '/api/subscriptions/' + encodeURIComponent(profile.token) +
    '/config.yaml?target=' + target;
}
async function api(path, options = {}) {
  const response = await fetch(path,{
    ...options, cache:'no-store',
    headers:{Authorization:'Bearer '+admin,
      ...(options.body ? {'Content-Type':'application/json'} : {}), ...options.headers}
  });
  const data = await response.json().catch(() => ({}));
  if(!response.ok) throw Error(data.error || 'HTTP ' + response.status);
  return data;
}
function activate() {
  el('login').classList.toggle('hidden',!!admin);
  el('workspace').classList.toggle('hidden',!admin);
  el('logout').classList.toggle('hidden',!admin);
}
function blank() {
  current=null;
  el('name').value='';el('sources').value='';el('manual').value='';el('rules').value='';
  el('editor-title').textContent='新建订阅';
  el('exports').classList.add('hidden');
  el('refresh').disabled=true;el('delete').disabled=true;
  el('refresh-interval').disabled=true;el('refresh-interval').value='0';
  el('node-filter-enabled').checked=false;
  el('node-filter-includes').value='';el('node-filter-excludes').value='';
  el('save-node-filter').disabled=true;
  el('refresh-status').textContent='保存配置后可设置自动刷新。';
  renderList();
}
function show(profile) {
  current=profile;
  el('name').value=profile.name;
  el('sources').value=(profile.source_urls||[]).join('\n');
  el('manual').value=profile.manual_yaml||'';
  el('rules').value=profile.rules_text||'';
  el('editor-title').textContent=profile.name;
  el('exports').classList.remove('hidden');
  el('refresh').disabled=false;el('delete').disabled=false;
  el('refresh-interval').disabled=false;
  el('save-node-filter').disabled=false;
  updateSchedule(profile.id);
  updateNodeFilter(profile.id);
  el('rs-url').textContent=link(profile,'clash-rs');
  el('mihomo-url').textContent=link(profile,'mihomo');
  renderList();
  updateQuota(profile.id);
}
function renderList() {
  el('count').textContent=String(profiles.length);
  const panel=el('profiles');panel.replaceChildren();
  profiles.forEach((profile)=>{
    const b=document.createElement('button');b.type='button';
    b.className='profile'+(current&&current.id===profile.id?' selected':'');
    const name=document.createElement('strong');name.textContent=profile.name;
    const subtitle=document.createElement('span');
    subtitle.textContent=String(profile.source_urls.length)+' 个源'+
      (profile.last_error ? ' · 上次刷新失败':'');
    b.append(name,subtitle);b.addEventListener('click',()=>show(profile));panel.append(b);
  });
  if(!profiles.length){const p=document.createElement('p');p.className='muted';
    p.textContent='暂无配置，点击「新建」开始。';panel.append(p);}
}
async function updateQuota(id) {
  try {
    const info=await api('/api/subscriptions/'+id+'/info');
    if(!current||current.id!==id)return;
    const parts=[];
    const gib=(v)=>(v/1073741824).toFixed(2)+' GiB';
    if(info.total!==null&&info.total!==undefined){
      const used=(info.upload||0)+(info.download||0);
      parts.push('已用 '+gib(used)+' / 总计 '+gib(info.total));
    }
    if(info.expire!==null&&info.expire!==undefined){
      parts.push('到期 '+new Date(info.expire*1000).toLocaleDateString());
    }
    el('quota-status').textContent=parts.length?parts.join(' · '):'订阅源暂无流量元数据';
  }catch(err){
    if(current&&current.id===id) el('quota-status').textContent='读取流量数据失败';
  }
}
async function reloadTemplates() {
  savedTemplates = await api('/api/templates');
  const selector = el('template-select');
  const previous = selector.value;
  selector.replaceChildren();
  const empty = document.createElement('option');
  empty.value='';empty.textContent='请选择预设或已保存模板';selector.append(empty);
  for(const t of savedTemplates) {
    const option = document.createElement('option');
    option.value=t.id;
    option.textContent=t.name+(t.built_in?' · 内置':' · 自定义');
    selector.append(option);
  }
  if(savedTemplates.some(t=>t.id===previous))selector.value=previous;
}
async function reload(id) {
  [profiles, savedTemplates] = await Promise.all([
    api('/api/subscriptions'),api('/api/templates')
  ]);
  const selector=el('template-select'), previous=selector.value;
  selector.replaceChildren();
  const empty=document.createElement('option');
  empty.value='';empty.textContent='请选择预设或已保存模板';
  selector.append(empty);
  savedTemplates.forEach(t=>{
    const option=document.createElement('option');
    option.value=t.id;option.textContent=t.name+(t.built_in?' · 内置':' · 自定义');
    selector.append(option);
  });
  if(savedTemplates.some(t=>t.id===previous))selector.value=previous;
  const next=profiles.find((p)=>p.id===(id||(current&&current.id)));
  if(next)show(next);else blank();
}
el('login-form').addEventListener('submit',async(e)=>{
  e.preventDefault();admin=el('token').value.trim();
  try{await reload();sessionStorage.setItem('subboost-rs-admin',admin);activate();notice('连接成功');}
  catch(err){admin='';notice(err.message,true);}
});
el('logout').addEventListener('click',()=>{
  sessionStorage.removeItem('subboost-rs-admin');admin='';profiles=[];blank();activate();
});
async function updateNodeFilter(id){
  try{
    const value=await api('/api/subscriptions/'+id+'/filter');
    if(!current||current.id!==id)return;
    el('node-filter-enabled').checked=!!value.enabled;
    el('node-filter-includes').value=(value.includeRegexes||[]).join('\n');
    el('node-filter-excludes').value=(value.excludeRegexes||[]).join('\n');
  }catch(err){notice(err.message,true);}
}
el('save-node-filter').addEventListener('click',async()=>{
  if(!current)return;
  const id=current.id;
  const lines=(name)=>el(name).value.split('\n').map(s=>s.trim()).filter(Boolean);
  try{
    await api('/api/subscriptions/'+id+'/filter',{method:'PUT',body:JSON.stringify({
      enabled:el('node-filter-enabled').checked,
      includeRegexes:lines('node-filter-includes'),
      excludeRegexes:lines('node-filter-excludes')
    })});
    notice('筛选条件已保存，后续生成配置自动应用');
  }catch(err){notice(err.message,true);}
});
async function updateSchedule(id){
  try{
    const info=await api('/api/subscriptions/'+id+'/schedule');
    if(!current||current.id!==id)return;
    el('refresh-interval').value=info?String(info.interval_seconds):'0';
    el('refresh-status').textContent=info?
      '下次检查：'+new Date(info.next_refresh_at*1000).toLocaleString()+
      ' · 连续失败：'+info.consecutive_failures : '自动刷新已关闭';
  }catch(err){notice(err.message,true);}
}
el('refresh-interval').addEventListener('change',async()=>{
  if(!current)return;
  const id=current.id,seconds=Number(el('refresh-interval').value);
  try {
    if(seconds===0)await api('/api/subscriptions/'+id+'/schedule',{method:'DELETE'});
    else await api('/api/subscriptions/'+id+'/schedule',{
      method:'PUT',body:JSON.stringify({interval_seconds:seconds})});
    await updateSchedule(id);
    notice(seconds===0?'已关闭定时更新':'已设置定时更新（失败后自动退避）');
  }catch(err){notice(err.message,true);}
});
el('new').addEventListener('click',blank);
el('apply-template').addEventListener('click',()=>{
  const value=savedTemplates.find(t=>t.id===el('template-select').value);
  if(!value){notice('请先选择模板',true);return;}
  if((el('manual').value.trim()||el('rules').value.trim()) &&
    !confirm('应用模板会覆盖当前配置的 YAML 与规则文本。继续吗？'))return;
  el('manual').value=value.manual_yaml;
  el('rules').value=value.rules_text;
  notice('已应用 '+value.name+'，请保存配置');
});
el('save-template').addEventListener('click',async()=>{
  const name=prompt('模板名称：',el('name').value.trim()||'自定义配置');
  if(name===null)return;
  try{
    const item=await api('/api/templates',{method:'POST',body:JSON.stringify({
      name:name.trim(),description:'保存于本地 SubBoost RS',
      manual_yaml:el('manual').value,rules_text:el('rules').value
    })});
    await reloadTemplates();
    el('template-select').value=item.id;
    notice('模板已保存到本机 SQLite');
  }catch(err){notice(err.message,true);}
});
el('delete-template').addEventListener('click',async()=>{
  const selected=savedTemplates.find(t=>t.id===el('template-select').value);
  if(!selected||selected.built_in){notice('请选择可删除的自定义模板',true);return;}
  if(!confirm('确定删除模板「'+selected.name+'」吗？'))return;
  try{
    await api('/api/templates/'+selected.id,{method:'DELETE'});
    await reloadTemplates();
    notice('模板已删除');
  }catch(err){notice(err.message,true);}
});

el('edit').addEventListener('submit',async(e)=>{
  e.preventDefault();
  const body={name:el('name').value.trim(),
    source_urls:el('sources').value.split('\n').map((v)=>v.trim()).filter(Boolean),
    manual_yaml:el('manual').value,rules_text:el('rules').value};
  try{
    const saved=await api(current?'/api/subscriptions/'+current.id:'/api/subscriptions',
      {method:current?'PUT':'POST',body:JSON.stringify(body)});
    await reload(saved.id);notice('已保存。远程源请点击刷新节点。');
  }catch(err){notice(err.message,true);}
});
el('refresh').addEventListener('click',async()=>{
  if(!current)return;
  el('refresh').disabled=true;
  try{
    const value=await api('/api/subscriptions/'+current.id+'/refresh',{method:'POST'});
    await reload(value.id);notice('节点已刷新并持久化');
  }catch(err){notice(err.message,true);}
  finally{el('refresh').disabled=!current;}
});
el('delete').addEventListener('click',async()=>{
  if(!current||!confirm('确定删除「'+current.name+'」吗？'))return;
  try{await api('/api/subscriptions/'+current.id,{method:'DELETE'});
    current=null;await reload();notice('已删除');}
  catch(err){notice(err.message,true);}
});
el('rotate').addEventListener('click',async()=>{
  if(!current||!confirm('这会使已经导入 Nikki-RS 的旧 URL 失效。继续吗？'))return;
  try{const v=await api('/api/subscriptions/'+current.id+'/rotate',{method:'POST'});
    await reload(v.id);notice('令牌已轮换，请同步更新 Nikki-RS 订阅链接');}
  catch(err){notice(err.message,true);}
});
async function copyLink(target){
  if(!current)return;
  try{await navigator.clipboard.writeText(link(current,target));notice('链接已复制');}
  catch(err){notice('无法访问剪贴板，请手动选中链接复制',true);}
}
el('copy-rs').addEventListener('click',()=>copyLink('clash-rs'));
el('copy-mihomo').addEventListener('click',()=>copyLink('mihomo'));
activate();
if(admin)reload().catch((err)=>{admin='';sessionStorage.removeItem('subboost-rs-admin');activate();notice(err.message,true);});