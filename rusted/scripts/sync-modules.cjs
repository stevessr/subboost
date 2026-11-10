// Build-time-only sync of the Rust embedded policy-group catalog.
// Requires Node.js for development, not for the router runtime.
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.resolve(__dirname,
  '../../packages/core/src/generator/proxy-group-modules.ts'),'utf8');
const marker = 'export const PROXY_GROUP_MODULES: ProxyGroupModule[] = [';
const start = source.indexOf(marker);
if (start < 0) throw new Error('Cannot find upstream module registry');
const open = source.indexOf('= [',start)+2;
const close = source.indexOf('\n];',open);
if (open<2 || close<0) throw new Error('Unexpected upstream module format');
const json = source.slice(open,close+2)
  .replace(/\/\/[^\n]*/g,'')
  .replace(/([,{]\s*)([A-Za-z][A-Za-z0-9_-]*)(\s*:)/g,'$1"$2"$3')
  .replace(/,\s*([}\]])/g,'$1');
const modules = JSON.parse(json);
if (!Array.isArray(modules) || modules.length<30 ||
    modules.some(m=>!m.id || !m.groupType || !Array.isArray(m.rules)))
  throw new Error('Upstream module registry missing expected entries');
const output=JSON.stringify(modules,null,2)+'\n';
const dest=path.resolve(__dirname,'../data/proxy-group-modules.json');
if (process.argv.includes('--check')) {
  if (fs.readFileSync(dest,'utf8')!==output) {
    throw new Error('Rust module snapshot out of sync: run node rusted/scripts/sync-modules.cjs');
  }
  console.log('SubBoost module catalog synchronized:',modules.length);
} else {
  fs.mkdirSync(path.dirname(dest),{recursive:true});
  fs.writeFileSync(dest,output);
  console.log('Wrote',dest,modules.length);
}
