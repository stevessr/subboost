'use strict';
const el = (id) => document.getElementById(id);
let admin = sessionStorage.getItem('subboost-rs-admin') || '';
let profiles = [], current = null;
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
  el('rs-url').textContent=link(profile,'clash-rs');
  el('mihomo-url').textContent=link(profile,'mihomo');
  renderList();
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
async function reload(id) {
  profiles=await api('/api/subscriptions');
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
el('new').addEventListener('click',blank);
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