#!/usr/bin/env node
// SysLens — serveur (récepteur syslog + console), Node.js sans dépendance. Licence MIT.
// Reçoit le syslog Zyxel (CEF/Syslog ou Syslog), le note par gravité, garde tout sur disque.
'use strict';
const cluster = require('cluster'), zlib = require('zlib'), dgram = require('dgram'), net = require('net'), http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto'), cp = require('child_process');
const SELFTEST = process.argv.includes('--selftest');
if (process.env.SYSLENS_WAIT_PID) { const pid = +process.env.SYSLENS_WAIT_PID, t0 = Date.now(), slot = new Int32Array(new SharedArrayBuffer(4));
  while (Date.now() - t0 < 15000) { try { process.kill(pid, 0); } catch (e) { break; } Atomics.wait(slot, 0, 0, 100); } delete process.env.SYSLENS_WAIT_PID; }
const PORT = +process.env.PORT || 514, WEB = +process.env.WEB || 8514, SHOW_BENIN = process.env.BENIN !== '0', BIND = process.env.BIND || '0.0.0.0';
const DIR = path.join(process.env.SYSLENS_DIR || __dirname, 'logs'); fs.mkdirSync(DIR, { recursive: true });
const SEV = ['emerg', 'alert', 'crit', 'error', 'warning', 'notice', 'info', 'debug'], BASE = [90, 90, 80, 65, 45, 25, 10, 0];
const level = s => s >= 85 ? 'critique' : s >= 60 ? 'grave' : s >= 30 ? 'moyen' : 'benin';
const COL = { critique: '\x1b[41;97m', grave: '\x1b[33m', moyen: '\x1b[93m', benin: '\x1b[2m' }, RST = '\x1b[0m';

// Mini-référentiel de départ : à remplacer par les vraies entrées (logs/types.json sert à ça).
const REF = [
  { k: 'if-stats', cat: /interface statistics/i, base: 10, telemetry: true },
  { k: 'admin-ok', re: /(logged in|login succe|has logged)/i, base: 45, admin: true, pubFloor: 85 },
  { k: 'admin-ko', re: /(fail|incorrect|wrong|invalid).*(login|password|authenticat)|(login|authenticat).*(fail|denied|reject)/i, base: 20, admin: true },
  { k: 'malware', cat: /anti-?malware|sandbox|anti-?virus/i, base: 80, floor: 85 },
  { k: 'iprep', cat: /ip reputation|dns threat|botnet/i, base: 75, floor: 85 },
  { k: 'idp', cat: /^(idp|adp)|intrusion/i, base: 60 },
  { k: 'vpn-down', cat: /ike|ipsec|vpn/i, re: /(down|disconnect|fail|dead peer|timeout|tear)/i, base: 55 },
  { k: 'link-down', re: /(link|port|interface|cable)[^,]*(down|disconnect)|status:down/i, base: 62 },
  { k: 'cfg', re: /(configuration|config)[^,]*(chang|modif|save|appl)|has been (changed|modified|applied)/i, base: 35, admin: true },
  { k: 'reboot', re: /(reboot|restart|system (is |has )?(start|boot))/i, base: 45 },
  { k: 'cpu', cat: /system monitoring/i, re: /cpu:(9\d|100)\b|memory:(9\d|100)\b/i, base: 40 }
];
const isPublic = ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.)/.test(ip);

const ip2n = ip => String(ip).split(".").reduce((a, o) => a * 256 + (+o || 0), 0);
const ALLOW = (process.env.ALLOW || "").split(",").map(c => c.trim()).filter(Boolean).map(c => { const [ip, b] = c.split("/"); return [ip2n(ip), b === undefined ? 32 : +b]; });
const allowed = ip => !ALLOW.length || ALLOW.some(([n, b]) => b === 0 || Math.floor(ip2n(ip) / 2 ** (32 - b)) === Math.floor(n / 2 ** (32 - b)));
let dropped = 0; const drop = a => { dropped++; if (dropped === 1 || dropped % 100 === 0) console.log("\x1b[2mIgnoré : log venant de " + a + " (hors " + process.env.ALLOW + "), " + dropped + " au total\x1b[0m"); };
function parse(raw, from) {
  const m = raw.match(/^<(\d{1,3})>([\s\S]*)$/), pri = m ? +m[1] : 13; let rest = m ? m[2] : raw;
  const ev = { t: Date.now(), from, raw, pri, sev: pri & 7, host: '', fmt: 'syslog', product: '', ver: '', cat: '', name: '', msg: '', f: {} };
  const h = rest.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)(?:\s\d{4})?\s(\S+)\s([\s\S]*)$/);
  if (h) { ev.host = h[2].replace(/:$/, ''); rest = h[3]; }
  const ci = rest.indexOf('CEF:');
  if (ci >= 0) {
    const c = rest.slice(ci + 4), parts = []; let cur = '', esc = false;
    for (const ch of c) { if (esc) { cur += ch; esc = false; } else if (ch === '\\') esc = true; else if (ch === '|' && parts.length < 7) { parts.push(cur); cur = ''; } else cur += ch; }
    parts.push(cur); ev.fmt = 'CEF'; ev.product = parts[2] || ''; ev.ver = parts[3] || ''; ev.name = parts[5] || '';
    const re = /(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|$)/g; let x; while ((x = re.exec(parts[7] || ''))) ev.f[x[1]] = x[2].replace(/\\=/g, '=').trim();
    if (ev.f.ZYlevel && SEV.includes(ev.f.ZYlevel.toLowerCase())) ev.sev = SEV.indexOf(ev.f.ZYlevel.toLowerCase());
  } else {
    const re = /(\w+)="([^"]*)"/g; let x; while ((x = re.exec(rest))) ev.f[x[1]] = x[2];
    if (Object.keys(ev.f).length) ev.fmt = 'ZLD';
  }
  if (!ev.product && /^(XMG|XGS|XS|GS|MG)\d/i.test(ev.host)) ev.product = ev.host;
  ev.cat = ev.f.cat || ev.name || ''; ev.msg = ev.f.msg || ev.name || rest.trim();
  ev.src = ev.f.src || ''; ev.dst = ev.f.dst || ''; ev.user = ev.f.suser || ev.f.user || '';
  return ev;
}
const win = new Map();
// ctx = false : note de base seule (processus de réception) ; ctx = true : avec répétitions, horaires et force brute (processus principal).
function score(ev, ctx = true) {
  const txt = ev.msg + ' ' + ev.name + ' ' + (ev.f.note || '') + ' ' + (ev.f.ZYnote || '');
  const r = REF.find(r => (!r.cat || r.cat.test(ev.cat)) && (!r.re || r.re.test(txt))), parts = [];
  ev.k = r ? r.k : 'non-reference'; ev.ref = !!(r && !r.telemetry);
  let s = r ? r.base : BASE[ev.sev]; parts.push((r ? 'référentiel ' + r.k : 'gravité Zyxel ' + SEV[ev.sev]) + ' ' + s);
  if (r && !r.telemetry && /USG|ATP|FLEX|ZyWALL|VPN/i.test(ev.product)) { s += 10; parts.push('pare-feu de tête +10'); }
  if (r && r.admin && isPublic(ev.src)) { s += 15; parts.push('IP publique +15'); }
  if (ctx) {
    const key = ev.k + '|' + ev.dev + '|' + ev.src, now = ev.t; let arr = win.get(key); if (!arr) win.set(key, arr = []);
    while (arr.length && now - arr[0] >= 300e3) arr.shift(); arr.push(now); if (arr.length > 250) arr.splice(0, arr.length - 250);
    const n = arr.length, rep = n >= 200 ? 20 : n >= 50 ? 15 : n >= 10 ? 10 : n >= 3 ? 5 : 0; if (rep && ev.ref) { s += rep; parts.push(n + ' en 5 min +' + rep); }
    const hr = new Date(now).getHours(); if (r && r.admin && (hr < 8 || hr >= 19)) { s += 10; parts.push('hors horaires +10'); }
    if (ev.k === 'admin-ko' && n >= 10) { s = Math.max(s, 60); parts.push('règle force brute'); }
  }
  if (r && r.pubFloor && isPublic(ev.src)) { s = Math.max(s, r.pubFloor); parts.push('admin depuis le WAN : critique'); }
  s = Math.min(100, Math.max(r && r.floor || 0, s, 0)); ev.score = s; ev.level = level(s); ev.why = parts.join(' · ');
}
// Fenêtre de répétition : les sources silencieuses depuis 5 min sont oubliées (sinon les scans d'Internet la font grossir sans fin).
setInterval(() => { const lim = Date.now() - 300e3; for (const [k, a] of win) if (!a.length || a[a.length - 1] < lim) win.delete(k); if (win.size > 500000) win.clear(); }, 60e3).unref();
// --- réception : un ou plusieurs processus (WORKERS). Chaque processus lit, note et archive le brut ;
// seuls les événements utiles (référentiel ou gravité moyen et plus) et un échantillon des bénins remontent au processus principal.
// Un processus suffit jusqu'à plusieurs dizaines de milliers de logs/s ; WORKERS=n en ajoute pour les très gros parcs.
const WORKERS = Math.max(0, Math.min(32, +process.env.WORKERS || 0)), RAW_GZ = process.env.RAW_GZIP !== '0';
const RETENTION = Math.max(1, +process.env.RETENTION_DAYS || 90), SAMPLE = Math.max(0, +(process.env.SAMPLE ?? 20)), HIST_MAX = 50000;
const day = () => new Date().toISOString().slice(0, 10);
const devKey = ev => ev.from + '|' + (ev.host || ev.f.devID || '');
// Écriture en flux, un fichier par jour ; le brut est compressé au fil de l'eau (gzip, environ 40 fois plus petit sur des logs Zyxel).
function dayWriter(name, gz) { let d = '', st = null, z = null;
  const w = line => { const t = day(); if (t !== d) { w.end(); d = t; st = fs.createWriteStream(path.join(DIR, name(t) + (gz ? '.gz' : '')), { flags: 'a' }); st.on('error', () => {});
    if (gz) { z = zlib.createGzip({ level: 1 }); z.on('error', () => {}); z.pipe(st); } } (z || st).write(line + '\n'); };
  w.end = () => { if (z) z.end(); else if (st) st.end(); z = st = null; };
  setInterval(() => { if (z) z.flush(); }, 5000).unref(); return w; }
const rawOut = dayWriter(t => 'raw-' + t + (cluster.isWorker ? '.w' + cluster.worker.id : '') + '.log', RAW_GZ);
const devDelta = new Map(), typeDelta = new Map(); let rxCount = 0, budget = SAMPLE, outBuf = [];
setInterval(() => { budget = SAMPLE; }, 1000).unref();
function stage1(line, from) {
  line = line.replace(/\r?\n$/, ''); if (!line.trim()) return;
  rawOut(line); rxCount++;
  const ev = parse(line, from); ev.dev = devKey(ev); score(ev, false);
  let d = devDelta.get(ev.dev); if (!d) devDelta.set(ev.dev, d = { key: ev.dev, from, host: ev.host, product: ev.product, ver: ev.ver, fmt: ev.fmt, count: 0, first: ev.t, last: 0 });
  d.count++; d.last = ev.t; if (ev.product) { d.product = ev.product; d.ver = ev.ver; }
  const tk = (ev.cat || '?') + ' | ' + (ev.name || ev.msg.slice(0, 60)); let ty = typeDelta.get(tk);
  if (!ty) typeDelta.set(tk, ty = { key: tk, cat: ev.cat, name: ev.name, count: 0, sev: SEV[ev.sev], k: ev.k, example: line }); ty.count++;
  if (ev.ref || ev.level !== 'benin') emit(ev, false); else if (budget > 0) { budget--; emit(ev, true); }
}
function emit(ev, sample) { if (cluster.isWorker) outBuf.push([ev, sample]); else stage2(ev, sample); }
function statsPayload() { const p = { n: rxCount, devs: [...devDelta.values()], types: [...typeDelta.values()] }; rxCount = 0; devDelta.clear(); typeDelta.clear(); return p; }
function startReceivers(h) {
  const udp = dgram.createSocket('udp4');
  udp.on('message', (b, ri) => allowed(ri.address) ? h(b.toString('utf8'), ri.address) : drop(ri.address));
  udp.on('listening', () => { try { udp.setRecvBufferSize(32 << 20); } catch (e) {} });
  udp.on('error', e => { console.error(`UDP ${PORT} : ${e.code}. ${e.code === 'EACCES' ? 'Relance avec sudo.' : e.code === 'EADDRINUSE' ? 'Le port est déjà pris par un autre service syslog.' : ''}`); process.exit(1); });
  const tcp = net.createServer(sk => { const ra = String(sk.remoteAddress).replace('::ffff:', ''); if (!allowed(ra)) { drop(ra); return sk.destroy(); }
    let buf = ''; sk.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { h(buf.slice(0, i), ra); buf = buf.slice(i + 1); } if (buf.length > 1 << 20) buf = ''; }); sk.on('error', () => {}); })
    .on('error', e => console.error('TCP ' + PORT + ' : ' + e.code + ' (UDP reste actif)'));
  udp.bind(PORT, BIND); tcp.listen(PORT, BIND); return { udp, tcp };
}
if (cluster.isWorker) {   // processus de réception : rien d'autre (ni console, ni mises à jour)
  if (!SELFTEST) startReceivers(stage1);
  setInterval(() => { if (outBuf.length) { process.send({ t: 'ev', evs: outBuf }); outBuf = []; } }, 50);
  setInterval(() => process.send({ t: 'stats', ...statsPayload() }), 1000);
  process.on('disconnect', () => { rawOut.end(); process.exit(0); });
  return;
}
// --- processus principal : notation complète, incidents, historique, console
const devices = new Map(), types = new Map(), recent = [], hist = [], incidents = new Map();
let SEQ = 0, total = 0, rate = 0, stopping = false, rx = null;
const evOut = dayWriter(t => 'events-' + t + '.jsonl');
function stage2(ev, sample, replay) {
  if (!sample && !replay) score(ev, true);
  ev.id = ++SEQ; hist.push(ev); if (hist.length > HIST_MAX * 1.1) hist.splice(0, hist.length - HIST_MAX);
  recent.push(ev); if (recent.length > 300) recent.shift();
  if (sample) return SHOW_BENIN && !WORKERS && console.log(`${new Date(ev.t).toLocaleTimeString('fr-FR')} ${ev.from.padEnd(15)} ${COL.benin}BENIN   ${RST} ${String(ev.score).padStart(3)}  ${(ev.cat || '-').slice(0, 22).padEnd(22)} ${ev.msg.slice(0, 90)}`);
  if (!replay) evOut(JSON.stringify(ev));
  if (ev.level !== 'benin') incident(ev);
  if (!replay) console.log(`${new Date(ev.t).toLocaleTimeString('fr-FR')} ${ev.from.padEnd(15)} ${COL[ev.level]}${ev.level.toUpperCase().padEnd(8)}${RST} ${String(ev.score).padStart(3)}  ${(ev.cat || '-').slice(0, 22).padEnd(22)} ${ev.msg.slice(0, 90)}`);
}
// Incidents agrégés côté serveur : un par (type, équipement, source), gardés 7 jours après le dernier événement.
function incident(ev) {
  const key = ev.k + '|' + ev.dev + '|' + ev.src; let I = incidents.get(key);
  if (I) incidents.delete(key); else I = { key, k: ev.k, dev: ev.dev, from: ev.from, host: ev.host, product: ev.product, src: ev.src, cat: ev.cat, first: ev.t, count: 0, score: 0, level: 'benin', samples: [] };
  I.count++; I.last = ev.t; I.msg = ev.msg; I.why = ev.why; if (ev.score >= I.score) { I.score = ev.score; I.level = ev.level; }
  I.samples.push(ev.raw); if (I.samples.length > 5) I.samples.shift(); incidents.set(key, I);
  if (incidents.size > 50000) incidents.delete(incidents.keys().next().value);
}
setInterval(() => { const lim = Date.now() - 7 * 864e5; for (const [k, I] of incidents) if (I.last < lim) incidents.delete(k); }, 600e3).unref();
function mergeStats(p) {
  total += p.n; rate += p.n;
  for (const x of p.devs) { let d = devices.get(x.key);
    if (!d) { d = { ...x, count: 0 }; devices.set(x.key, d); console.log(`\n\x1b[32m✓ Premier log reçu de ${x.from}${x.host ? ' (' + x.host + ')' : ''}${x.product ? ' : ' + x.product + ' ' + x.ver : ''} (format ${x.fmt})\x1b[0m\n`); }
    d.count += x.count; d.last = Math.max(d.last || 0, x.last); if (x.product) { d.product = x.product; d.ver = x.ver; } }
  for (const x of p.types) { let ty = types.get(x.key); if (!ty) { if (types.size >= 5000) continue; types.set(x.key, ty = { ...x, count: 0 }); } ty.count += x.count; }
}
let lastRate = 0; setInterval(() => { lastRate = Math.round(rate / 10); rate = 0; }, 10e3).unref();
setInterval(() => { if (!WORKERS) mergeStats(statsPayload()); }, 1000).unref();
setInterval(() => fs.writeFile(path.join(DIR, 'types.json'), JSON.stringify([...types.values()].sort((a, b) => b.count - a.count), null, 2), () => {}), 15e3).unref();
// Archives : les jours passés sont compressés, au-delà de RETENTION_DAYS (90 par défaut) ils sont supprimés.
function maintain() { const today = day(), lim = new Date(Date.now() - RETENTION * 864e5).toISOString().slice(0, 10);
  let names = []; try { names = fs.readdirSync(DIR); } catch (e) { return; }
  for (const f of names) { const m = /^(?:raw|events)-(\d{4}-\d{2}-\d{2})(?:\.w\d+)?\.(?:log|jsonl)(\.gz)?$/.exec(f); if (!m) continue; const p = path.join(DIR, f);
    if (m[1] < lim) { fs.rmSync(p, { force: true }); continue; }
    if (m[1] < today && !m[2]) { try { if (Date.now() - fs.statSync(p).mtimeMs < 600e3) continue; } catch (e) { continue; }
      const tmp = p + '.gz.part'; require('stream').pipeline(fs.createReadStream(p), zlib.createGzip(), fs.createWriteStream(tmp), err => { if (err) return fs.rmSync(tmp, { force: true }); fs.renameSync(tmp, p + '.gz'); fs.rmSync(p, { force: true }); }); } } }
function startWorkers() {
  cluster.setupPrimary({ silent: false });
  const onMsg = m => { if (m && m.t === 'ev') for (const [ev, sm] of m.evs) stage2(ev, sm); else if (m && m.t === 'stats') mergeStats(m); };
  for (let i = 0; i < WORKERS; i++) cluster.fork().on('message', onMsg);
  cluster.on('exit', (w, code) => { if (stopping) return; console.log(`\x1b[33mProcessus de réception ${w.id} arrêté (${code}), relance.\x1b[0m`); setTimeout(() => cluster.fork().on('message', onMsg), 1000); });
}

const PAGE = `<!DOCTYPE html><html lang="fr"><meta charset="utf-8"><title>SysLens — test</title><style>body{font:14px system-ui;background:#0b100e;color:#e5ede9;margin:24px}h1{font-size:20px}table{border-collapse:collapse;width:100%;margin:10px 0 26px}td,th{padding:5px 8px;border-bottom:1px solid #1c2622;text-align:left;vertical-align:top}th{color:#7a8a83;font-weight:400}.critique{color:#ff5a5f;font-weight:600}.grave{color:#ff9248}.moyen{color:#f0c94a}.benin{color:#7a8a83}code{font-size:12px;color:#7a8a83}</style><h1>SysLens — récepteur de test</h1><div id="v">Chargement…</div><script>
const e=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function go(){const d=await (await fetch('/api')).json();document.getElementById('v').innerHTML=
'<h2>Équipements ('+d.devices.length+')</h2><table><tr><th>IP</th><th>Modèle</th><th>Firmware</th><th>Logs</th><th>Dernier</th></tr>'+d.devices.map(x=>'<tr><td>'+e(x.from)+'</td><td>'+e(x.product||x.host)+'</td><td>'+e(x.ver)+'</td><td>'+x.count+'</td><td>'+new Date(x.last).toLocaleTimeString('fr-FR')+'</td></tr>').join('')+'</table>'+
'<h2>Derniers logs</h2><table><tr><th>Heure</th><th>Niveau</th><th>Score</th><th>Catégorie</th><th>Message</th><th>Calcul</th></tr>'+d.events.map(x=>'<tr><td>'+new Date(x.t).toLocaleTimeString('fr-FR')+'</td><td class="'+x.level+'">'+x.level+'</td><td>'+x.score+'</td><td>'+e(x.cat)+'</td><td>'+e(x.msg)+'</td><td><code>'+e(x.why)+'</code></td></tr>').join('')+'</table>'+
'<h2>Types de logs vus ('+d.types.length+')</h2><table><tr><th>Nb</th><th>Catégorie</th><th>Nom</th><th>Gravité Zyxel</th><th>Règle</th></tr>'+d.types.map(x=>'<tr><td>'+x.count+'</td><td>'+e(x.cat)+'</td><td>'+e(x.name)+'</td><td>'+x.sev+'</td><td>'+x.k+'</td></tr>').join('')+'</table>';}
go();setInterval(go,2000);</script></html>`;
try { const fe = path.join(DIR, 'events-' + day() + '.jsonl');
  // Le fichier du jour ne garde que les événements utiles (avec leur ligne brute) : rechargement rapide même à fort débit.
  for (const l of fs.readFileSync(fe, 'utf8').split('\n')) { if (!l) continue; let e; try { e = JSON.parse(l); } catch (x) { continue; }
    if (!allowed(e.from)) continue; e.raw = e.raw || ''; e.f = e.f || {}; e.dev = e.dev || e.from + '|' + (e.host || ''); stage2(e, false, true);
    let d = devices.get(e.dev); if (!d) devices.set(e.dev, d = { key: e.dev, from: e.from, host: e.host, product: e.product, ver: e.ver, fmt: e.fmt, first: e.t, count: 0 }); d.last = e.t; d.count++; }
  if (hist.length) console.log('Historique du jour rechargé : ' + hist.length + ' événements utiles');
} catch (e) {}
// --- logos d'extension : récupérés une fois sur le site officiel de la marque, puis gardés dans extensions/<id>/
const EXT_SITES = Object.assign({ zyxel: 'https://www.zyxel.com', odoo: 'https://www.odoo.com', telegram: 'https://telegram.org', unifi: 'https://ui.com', fortinet: 'https://www.fortinet.com', cisco: 'img:https://upload.wikimedia.org/wikipedia/commons/0/08/Cisco_logo_blue_2016.svg',
  ollama: 'https://ollama.com', mistral: 'https://mistral.ai', chatgpt: 'https://chatgpt.com', claude: 'https://www.claude.com', hermes: 'https://nousresearch.com', grok: 'https://grok.com', 
  // Gemini, Codex, Claude Code et Gemini CLI n'ont pas d'icône propre sur leur site : image directe (collection LobeHub Icons).
  gemini: 'img:https://unpkg.com/@lobehub/icons-static-svg@latest/icons/gemini-color.svg', codex: 'img:https://unpkg.com/@lobehub/icons-static-svg@latest/icons/codex-color.svg', claudecode: 'img:https://unpkg.com/@lobehub/icons-static-svg@latest/icons/claudecode-color.svg', geminicli: 'img:https://unpkg.com/@lobehub/icons-static-svg@latest/icons/geminicli-color.svg' }, JSON.parse(process.env.EXT_SITES || '{}'));
const LOGO_EXT = { 'image/svg+xml': 'svg', 'image/png': 'png', 'image/x-icon': 'ico', 'image/vnd.microsoft.icon': 'ico', 'image/jpeg': 'jpg', 'image/webp': 'webp' };
const LOGO_CT = Object.fromEntries(Object.entries(LOGO_EXT).map(([c, e]) => [e, c]));
const logoJobs = new Map();
const logoFile = dir => { try { const have = fs.readdirSync(dir), f = ['svg', 'png', 'webp', 'jpg', 'ico'].map(e => 'logo.' + e).find(n => have.includes(n)); return f && path.join(dir, f); } catch (e) { return null; } };
async function getBytes(url, max) { const r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'SysLens/0.1 (extension logo)' } });
  if (!r.ok) throw new Error('HTTP ' + r.status); const b = Buffer.from(await r.arrayBuffer()); if (b.length > max) throw new Error('trop gros'); return { b, url: r.url, ct: (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() }; }
// Le contenu doit être une vraie image : un site protégé renvoie parfois une page HTML à l'adresse de l'icône.
function isImage(b, ext) { const head = b.toString('utf8', 0, 4096);
  if (ext === 'svg') return /^\s*(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*)*(<!DOCTYPE[^>]*>\s*)?<svg[\s>]/i.test(head) && !/<html[\s>]/i.test(head);
  if (ext === 'png') return b.length > 8 && b.readUInt32BE(0) === 0x89504e47;
  if (ext === 'ico') return b.length > 6 && b.readUInt32BE(0) === 0x00000100;
  if (ext === 'jpg') return b[0] === 0xff && b[1] === 0xd8;
  if (ext === 'webp') return b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP';
  return false; }
async function fetchLogo(id, dir) {
  const site = EXT_SITES[id]; if (!site) throw new Error('pas de site officiel déclaré');
  if (site.startsWith('img:')) return saveLogo(id, dir, site, [{ u: site.slice(4) }]);
  const page = await getBytes(site, 3e6), html = page.b.toString('utf8'), cands = [];
  for (const tag of html.match(/<link\b[^>]*>/gi) || []) {
    const at = k => (new RegExp('\\b' + k + '\\s*=\\s*["\']([^"\']+)', 'i').exec(tag) || [])[1] || '';
    const rel = at('rel').toLowerCase(), href = at('href'); if (!href || !/icon/.test(rel) || /mask-icon/.test(rel)) continue;
    const size = Math.max(0, ...at('sizes').split(/\s+/).map(s => parseInt(s, 10) || 0)), svg = /svg/.test(at('type')) || /\.svg(\?|$)/i.test(href);
    cands.push({ u: new URL(href, page.url).href, s: svg ? 1000 : /apple-touch-icon/.test(rel) ? 500 + size : size || 1 }); }
  cands.sort((a, b) => b.s - a.s); cands.push({ u: new URL('/favicon.ico', page.url).href });
  return saveLogo(id, dir, site, cands); }
async function saveLogo(id, dir, site, cands) {
  for (const c of cands) { try { const img = await getBytes(c.u, 512e3), ext = LOGO_EXT[img.ct] || (/\.svg(\?|$)/i.test(c.u) ? 'svg' : /\.ico(\?|$)/i.test(c.u) ? 'ico' : '');
      if (!ext || !isImage(img.b, ext)) continue;
      fs.mkdirSync(dir, { recursive: true }); const f = path.join(dir, 'logo.' + ext); fs.writeFileSync(f, img.b);
      for (const o of Object.values(LOGO_EXT)) if (o !== ext) try { fs.unlinkSync(path.join(dir, 'logo.' + o)); } catch (e) {}
      fs.writeFileSync(path.join(dir, 'source.txt'), `Logo récupéré le ${new Date().toISOString()}\nsur ${img.url}\n(site officiel déclaré : ${site})\nSupprimer ce dossier pour le récupérer à nouveau.\n`);
      try { fs.unlinkSync(path.join(dir, 'logo.fail')); } catch (e) {}
      console.log(`\x1b[32m✓ Logo ${id} installé (${ext}, ${img.b.length} o) depuis ${img.url}\x1b[0m`); return f; } catch (e) {} }
  throw new Error('aucune icône exploitable sur ' + site); }
function extLogo(id, r, fmt) {
  const dir = path.join(__dirname, 'extensions', id), send = f => { r.writeHead(302, { location: '/ext/' + id + '/' + path.basename(f), 'cache-control': 'no-store' }); r.end(); };
  if (fmt) { const f = path.join(dir, 'logo.' + fmt); if (!fs.existsSync(f)) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'content-type': LOGO_CT[f.split('.').pop()], 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox" }); return fs.createReadStream(f).pipe(r); }
  // Logo en cache : resservi tel quel, sauf si sa source a changé dans une nouvelle version (il est alors remplacé, l'ancien sert en attendant).
  const have = logoFile(dir); let src = ''; try { src = fs.readFileSync(path.join(dir, 'source.txt'), 'utf8'); } catch (e) {}
  const stale = have && EXT_SITES[id] && src && !src.includes('(site officiel déclaré : ' + EXT_SITES[id] + ')');
  if (have && !stale) return send(have);
  const fail = path.join(dir, 'logo.fail'); try { if (Date.now() - fs.statSync(fail).mtimeMs < 24 * 3600e3) { if (have) return send(have); r.writeHead(404); return r.end(); } } catch (e) {}
  if (!logoJobs.has(id)) logoJobs.set(id, fetchLogo(id, dir).finally(() => logoJobs.delete(id)));
  logoJobs.get(id).then(send, err => { if (EXT_SITES[id]) { try { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(fail, err.message + '\n'); } catch (e) {} console.log(`\x1b[2mLogo ${id} : ${err.message} (nouvel essai dans 24 h)\x1b[0m`); } if (have) return send(have); r.writeHead(404); r.end(); });
}
// --- Telegram : vérification du bot, détection du groupe (/start puis /configurate), message de test
async function tg(token, method, body) {
  if (!/^\d{6,}:[\w-]{20,}$/.test(token || '')) throw new Error('Jeton invalide.');
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}), signal: AbortSignal.timeout(10000) });
  const j = await r.json().catch(() => ({})); if (!j.ok) throw new Error(j.error_code === 401 ? 'Jeton refusé par Telegram.' : /webhook/i.test(j.description || '') ? 'Ce bot utilise déjà un webhook : supprimez-le ou utilisez un autre bot.' : (j.description || 'Telegram ne répond pas.')); return j.result; }
async function tgApi(q) {
  if (q.op === 'me') { const me = await tg(q.token, 'getMe'); return { username: me.username }; }
  if (q.op === 'detect') {
    const ups = await tg(q.token, 'getUpdates', { timeout: 0, allowed_updates: ['message'] }), started = new Set(); let hit = null;
    for (const u of ups) { const m = u.message; if (!m || !m.text || !m.chat) continue;
      const cmd = m.text.trim().split(/\s+/)[0].toLowerCase().replace(/@\w+$/, '');
      if (cmd === '/start') started.add(m.chat.id);
      else if (cmd === '/configurate' && started.has(m.chat.id)) hit = { chat: String(m.chat.id), title: m.chat.title || [m.chat.first_name, m.chat.last_name].filter(Boolean).join(' ') || 'Discussion', last: u.update_id }; }
    if (!hit) return { found: false };
    await tg(q.token, 'getUpdates', { offset: hit.last + 1, timeout: 0 });
    await tg(q.token, 'sendMessage', { chat_id: hit.chat, text: 'SysLens : groupe reconnu. Les alertes arriveront ici.' }).catch(() => {});
    return { found: true, chat: hit.chat, title: hit.title }; }
  if (q.op === 'send') { await tg(q.token, 'sendMessage', { chat_id: q.chat, text: `SysLens — message de test\nLes alertes de niveau ${String(q.lv || 'critique').slice(0, 60)} arriveront dans ce groupe.` }); return { sent: true }; }
  throw new Error('Opération inconnue.'); }
// --- IA : liste des modèles (vérifie la clé ou l'adresse Ollama) et présence de Codex / Claude Code
const AI_API = { chatgpt: ['https://api.openai.com/v1/models', 'bearer'], mistral: ['https://api.mistral.ai/v1/models', 'bearer'], grok: ['https://api.x.ai/v1/models', 'bearer'], hermes: ['https://inference-api.nousresearch.com/v1/models', 'bearer'], gemini: ['https://generativelanguage.googleapis.com/v1beta/models?pageSize=200', 'google'], claude: ['https://api.anthropic.com/v1/models?limit=100', 'anthropic'] };
// --- Abonnements (Codex, Claude Code, Gemini CLI) : installés par SysLens dans son dossier outils/ (sans droits administrateur),
// puis connexion au compte : l'outil ouvre la page de connexion du fournisseur, SysLens suit la fin tout seul.
const CLI = {
  codex: { bin: 'codex', pkg: '@openai/codex', login: ['login'], status: run => run(['login', 'status']).status === 0 },
  claudecode: { bin: 'claude', pkg: '@anthropic-ai/claude-code', login: ['auth', 'login', '--claudeai'], code: true,
    status: run => { try { return JSON.parse(run(['auth', 'status', '--json']).stdout).loggedIn === true; } catch (e) { return false; } } },
  geminicli: { bin: 'gemini', pkg: '@google/gemini-cli', login: ['-p', 'OK'], env: { GOOGLE_GENAI_USE_GCA: 'true', GEMINI_CLI_TRUST_WORKSPACE: 'true' },
    status: () => fs.existsSync(path.join(os.homedir(), '.gemini', 'oauth_creds.json')) } };
const OUTILS = path.join(__dirname, 'outils'), WIN = process.platform === 'win32', cliJobs = {};
const LOGIN_HOSTS = /^https:\/\/(auth\.openai\.com|(platform\.|www\.)?claude\.(com|ai)|console\.anthropic\.com|accounts\.google\.com)\//;
const cliEnv = t => ({ ...process.env, ...(t.env || {}), PATH: path.dirname(process.execPath) + path.delimiter + (process.env.PATH || '') });
const cliBin = t => { const local = path.join(OUTILS, 'node_modules', '.bin', t.bin + (WIN ? '.cmd' : '')); return fs.existsSync(local) ? local : t.bin; };
const cliRun = t => args => cp.spawnSync(cliBin(t), args, { encoding: 'utf8', timeout: 15000, env: cliEnv(t), shell: WIN });
const strip = x => String(x).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '');
function cliStatus(id) { const t = CLI[id], j = cliJobs[id], v = cliRun(t)(['--version']);
  const job = j && { phase: j.phase, url: j.url || '', err: j.err || '', code: !!t.code };
  if (v.error || v.status !== 0) return { installed: false, job };
  return { installed: true, version: strip(v.stdout || v.stderr).trim().split('\n')[0].slice(0, 80), logged: !(j && j.phase) && t.status(cliRun(t)), job }; }
function cliStart(id, phase) { const t = CLI[id], old = cliJobs[id]; if (old && old.phase) return; const j = cliJobs[id] = { phase, out: '' };
  let proc;
  if (phase === 'install') { fs.mkdirSync(OUTILS, { recursive: true });
    const npm = path.join(path.dirname(process.execPath), WIN ? 'npm.cmd' : 'npm');
    proc = cp.spawn(fs.existsSync(npm) ? npm : 'npm', ['install', '--prefix', OUTILS, '--no-audit', '--no-fund', '--loglevel=error', t.pkg + '@latest'], { env: cliEnv(t), shell: WIN }); }
  else proc = cp.spawn(cliBin(t), t.login, { env: cliEnv(t), cwd: OUTILS, shell: WIN });
  j.proc = proc; console.log(`\x1b[2m${t.bin} : ${phase === 'install' ? 'installation de ' + t.pkg : 'connexion au compte'} en cours\x1b[0m`);
  const tick = setInterval(() => { if (id === 'geminicli' && phase === 'login' && t.status()) proc.kill(); }, 2000);
  const kill = setTimeout(() => { j.err = 'Délai dépassé.'; proc.kill(); }, phase === 'install' ? 10 * 60e3 : 15 * 60e3);
  const read = d => { j.out = (j.out + strip(d)).slice(-20000);
    if (!j.url) { const u = (j.out.match(/https:\/\/[^\s"'<>]+/g) || []).find(x => LOGIN_HOSTS.test(x)); if (u) j.url = u; }
    if (/\[Y\/n\]/.test(j.out) && !j.yes) { j.yes = true; proc.stdin.write('y\n'); } };
  proc.stdout.on('data', read); proc.stderr.on('data', read); proc.on('error', e => { j.err = e.message; });
  proc.on('close', code => { clearInterval(tick); clearTimeout(kill); j.phase = '';
    const ok = phase === 'install' ? code === 0 : t.status(cliRun(t));
    if (!ok && !j.err) j.err = phase === 'install' ? 'Installation impossible : ' + (j.out.trim().split('\n').pop() || 'npm a échoué') : 'Connexion non terminée.';
    console.log(`\x1b[${ok ? '32m✓' : '2m'} ${t.bin} : ${phase === 'install' ? 'installation' : 'connexion'} ${ok ? 'terminée' : 'échouée'}\x1b[0m`); }); }
async function aiApi(q) {
  if (['cli', 'install', 'login', 'code', 'cancel'].includes(q.op)) { const t = CLI[q.tool]; if (!t) throw new Error('Outil inconnu.'); const j = cliJobs[q.tool];
    if (q.op === 'install') cliStart(q.tool, 'install');
    if (q.op === 'login') { if (!cliStatus(q.tool).installed) throw new Error('Outil non installé.'); cliStart(q.tool, 'login'); }
    if (q.op === 'code') { const c = String(q.code || '').trim(); if (!t.code || !j || j.phase !== 'login') throw new Error('Aucune connexion en attente.');
      if (!/^[\w#.~-]{8,512}$/.test(c)) throw new Error('Code invalide.'); j.proc.stdin.write(c + '\n'); }
    if (q.op === 'cancel' && j && j.phase) { j.err = 'Annulé.'; j.proc.kill(); }
    // Connexion : on attend que l'outil ait affiché l'adresse de la page (3 s au plus), pour la proposer tout de suite.
    for (let i = 0; q.op !== 'cli' && i < 30; i++) { const k = cliJobs[q.tool]; if (q.op !== 'login' || !k || !k.phase || k.url) break; await new Promise(r => setTimeout(r, 100)); }
    return cliStatus(q.tool); }
  if (q.op === 'models') {
    if (q.provider === 'ollama') { let u; try { u = new URL('/api/tags', String(q.url || '')); } catch (e) { throw new Error('Adresse invalide.'); } if (!/^https?:$/.test(u.protocol)) throw new Error('Adresse invalide.');
      const r = await fetch(u, { signal: AbortSignal.timeout(8000) }).catch(() => { throw new Error('Ollama ne répond pas à ' + u.origin + '.'); });
      if (!r.ok) throw new Error('Ollama a répondu ' + r.status + '.'); return { models: ((await r.json()).models || []).map(m => m.name).sort() }; }
    const a = AI_API[q.provider], key = String(q.key || '').trim(); if (!a) throw new Error('Fournisseur inconnu.'); if (key.length < 20 || /\s/.test(key)) throw new Error('Clé invalide.');
    const r = await fetch(a[0], { headers: a[1] === 'anthropic' ? { 'x-api-key': key, 'anthropic-version': '2023-06-01' } : a[1] === 'google' ? { 'x-goog-api-key': key } : { authorization: 'Bearer ' + key }, signal: AbortSignal.timeout(10000) }).catch(() => { throw new Error('Le fournisseur ne répond pas.'); });
    if (r.status === 401 || r.status === 403 || (a[1] === 'google' && r.status === 400)) throw new Error('Clé refusée par le fournisseur.'); if (!r.ok) throw new Error('Le fournisseur a répondu ' + r.status + '.');
    const j = await r.json(); return { models: (j.data || j.models || []).map(m => m.id || String(m.name || '').replace(/^models\//, '')).filter(Boolean).sort() }; }
  throw new Error('Opération inconnue.'); }
const sameOrigin = q => { const o = q.headers.origin; return (!o || /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(o)) && /application\/json/.test(q.headers['content-type'] || ''); };
const webSrv = http.createServer((q, r) => {
  if (q.url === '/api/version') { let news = []; try { news = JSON.parse(fs.readFileSync(path.join(__dirname, 'nouveautes.json'), 'utf8')).slice(0, 5); } catch (e) {} r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify({ ...upd, news })); }
  else if (q.url === '/api/update' && q.method === 'POST') { const json = o => { r.writeHead(sameOrigin(q) ? 200 : 403, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json({ error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 256) q.destroy(); });
    q.on('end', async () => { let install = false; try { install = !!JSON.parse(body).install; } catch (e) {} json(await checkUpdate(install)); }); }
  else if (q.url.startsWith('/api/events')) { const since = +(new URL(q.url, 'http://x').searchParams.get('since') || 0); r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); const evs = []; for (let i = hist.length - 1; i >= 0 && hist[i].id > since && evs.length < 5000; i--) evs.push(hist[i]); evs.reverse();
    r.end(JSON.stringify({ version: VERSION, stats: { rate: lastRate, total, workers: WORKERS, devices: devices.size, incidents: incidents.size }, devices: [...devices.values()], events: evs })); }
  else if (q.url.startsWith('/api/incidents')) { const lv = new URL(q.url, 'http://x').searchParams.get('level'); const out = []; for (const I of incidents.values()) if (!lv || I.level === lv) out.push(I);
    out.sort((a, b) => b.last - a.last); r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify({ total: out.length, incidents: out.slice(0, 2000) })); }
  else if (q.url.startsWith('/console')) { fs.readFile(path.join(__dirname, 'console.html'), (err, b) => { r.writeHead(err ? 404 : 200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); r.end(err ? 'console.html introuvable' : b); }); }
  else if (q.url === '/api/ai' && q.method === 'POST') {
    const json = (code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json(403, { error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 8192) q.destroy(); });
    q.on('end', async () => { try { json(200, await aiApi(JSON.parse(body))); } catch (e) { json(400, { error: e.message }); } }); }
  else if (q.url === '/api/tg' && q.method === 'POST') {
    const json = (code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json(403, { error: 'Refusé.' });
    let body = ''; q.on('data', d => { body += d; if (body.length > 4096) q.destroy(); });
    q.on('end', async () => { try { json(200, await tgApi(JSON.parse(body))); } catch (e) { json(400, { error: e.message }); } }); }
  else if (q.url.startsWith('/ext/')) { const m = /^\/ext\/([a-z0-9-]+)\/logo(?:\.(svg|png|webp|jpg|ico))?$/.exec(q.url.split('?')[0]); if (m) extLogo(m[1], r, m[2]); else { r.writeHead(404); r.end(); } }
  else if (q.url === '/api') { r.writeHead(200, { 'content-type': 'application/json' }); r.end(JSON.stringify({ devices: [...devices.values()], events: recent.slice(-150).reverse().map(({ raw, ...x }) => x), types: [...types.values()].sort((a, b) => b.count - a.count) })); }
  else { r.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); r.end(PAGE); }
});


// --- mise à jour automatique : suit les releases GitHub du dépôt (fichiers vérifiés par SHA256SUMS)
const PKG = (() => { try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')); } catch (e) { return {}; } })();
const VERSION = 'v' + String(PKG.version || '0.0.0').replace(/^v/, ''), REPO = process.env.SYSLENS_REPO || (PKG.syslens && PKG.syslens.repo) || 'Nesaris/SysLens';
const GH_API = process.env.SYSLENS_GH_API || 'https://api.github.com', GH_RAW = process.env.SYSLENS_GH_RAW || 'https://raw.githubusercontent.com';
const upd = { version: VERSION, repo: REPO, auto: process.env.SYSLENS_AUTOUPDATE !== '0', latest: null, checkedAt: null, state: 'idle', msg: '' };
const semv = v => String(v).replace(/^v/, '').split(/[.+-]/).slice(0, 3).map(n => +n || 0), newer = (a, b) => { const x = semv(a), y = semv(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i]; return false; };
async function ghGet(url, raw) { const r = await fetch(url, { headers: { 'user-agent': 'SysLens/' + VERSION, accept: raw ? '*/*' : 'application/vnd.github+json' }, signal: AbortSignal.timeout(20000) });
  if (r.status === 404 && !raw) throw new Error('Aucune release publiée sur ' + REPO + '.'); if (!r.ok) throw new Error('GitHub a répondu ' + r.status + '.'); return raw ? Buffer.from(await r.arrayBuffer()) : r.json(); }
async function checkUpdate(install) {
  if (upd.state === 'installing' || upd.state === 'checking') return upd;
  upd.state = 'checking';
  try {
    const rel = await ghGet(`${GH_API}/repos/${REPO}/releases/latest`); upd.latest = rel.tag_name; upd.checkedAt = Date.now(); upd.url = rel.html_url;
    if (!newer(rel.tag_name, VERSION)) { upd.state = 'idle'; upd.msg = 'À jour.'; return upd; }
    if (!install) { upd.state = 'available'; upd.msg = rel.tag_name + ' disponible.'; return upd; }
    upd.state = 'installing'; console.log(`\x1b[36m↻ Mise à jour ${VERSION} → ${rel.tag_name}…\x1b[0m`);
    const base = `${GH_RAW}/${REPO}/${encodeURIComponent(rel.tag_name)}/`;
    const files = (await ghGet(base + 'SHA256SUMS', true)).toString('utf8').split('\n').map(l => l.trim().split(/\s+/)).filter(x => x.length === 2).map(([h, f]) => [h.toLowerCase(), f.replace(/^\*/, '')]);
    if (!files.some(([, f]) => f === 'syslens.js') || files.some(([h, f]) => !/^[a-f0-9]{64}$/.test(h) || !/^[\w][\w.-]*$/.test(f))) throw new Error('SHA256SUMS de la release invalide.');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'syslens-'));
    try {
      for (const [h, f] of files) { const b = await ghGet(base + f, true); if (crypto.createHash('sha256').update(b).digest('hex') !== h) throw new Error('Empreinte incorrecte pour ' + f + ', mise à jour annulée.'); fs.writeFileSync(path.join(tmp, f), b); }
      const t = cp.spawnSync(process.execPath, [path.join(tmp, 'syslens.js'), '--selftest'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, SYSLENS_DIR: tmp } });
      if (t.status !== 0) throw new Error('La nouvelle version ne démarre pas : ' + String(t.stderr || t.stdout).slice(0, 300));
      const bak = path.join(__dirname, '.previous'); fs.rmSync(bak, { recursive: true, force: true }); fs.mkdirSync(bak);
      for (const [, f] of files) { const cur = path.join(__dirname, f); if (fs.existsSync(cur)) fs.copyFileSync(cur, path.join(bak, f)); }
      for (const [, f] of files) { fs.copyFileSync(path.join(tmp, f), path.join(__dirname, f + '.new')); fs.renameSync(path.join(__dirname, f + '.new'), path.join(__dirname, f)); }
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
    console.log(`\x1b[32m✓ SysLens ${rel.tag_name} installé (ancienne version gardée dans .previous/), redémarrage…\x1b[0m`); upd.msg = rel.tag_name + ' installé, redémarrage.'; setTimeout(restart, 300);
  } catch (e) { upd.state = 'error'; upd.msg = e.message; upd.checkedAt = Date.now(); console.log(`\x1b[33mMise à jour : ${e.message}\x1b[0m`); }
  return upd; }
function restart() { let gone = false; stopping = true; const go = () => { if (gone) return; gone = true; cp.spawn(process.execPath, process.argv.slice(1), { stdio: 'inherit', env: { ...process.env, SYSLENS_WAIT_PID: String(process.pid) } }); process.exit(0); };
  setTimeout(go, 4000); evOut.end(); rawOut.end();
  if (rx) { try { rx.udp.close(); } catch (e) {} rx.tcp.close(); } for (const w of Object.values(cluster.workers || {})) w.kill();
  webSrv.close(() => setTimeout(go, 300)); if (webSrv.closeAllConnections) webSrv.closeAllConnections(); }

if (SELFTEST) { console.log('selftest ok ' + VERSION); process.exit(0); }
if (WORKERS) startWorkers(); else rx = startReceivers(stage1);
setTimeout(maintain, 5000).unref(); setInterval(maintain, 3600e3).unref();
setInterval(() => { if (lastRate || incidents.size) console.log(`\x1b[2mDébit ${lastRate} logs/s · ${devices.size} équipements · ${incidents.size} incidents · ${WORKERS || 1} processus de réception\x1b[0m`); }, 300e3).unref();
webSrv.listen(WEB, '127.0.0.1', () => {
  const ips = Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal).map(i => i.address);
  console.log(`SysLens ${VERSION} — écoute syslog UDP et TCP ${BIND}:${PORT} (${WORKERS ? WORKERS + ' processus de réception' : '1 processus'})${ALLOW.length ? ', logs acceptés seulement depuis ' + process.env.ALLOW : ''}\nIP à mettre dans le USG (serveur distant) : ${ips.join(' ou ') || 'aucune IP détectée'}\nPage de suivi : http://localhost:${WEB}\nConsole SysLens : http://localhost:${WEB}/console\nFichiers : ${DIR}\nMise à jour auto : ${upd.auto ? 'activée (' + REPO + ', releases)' : 'désactivée'}\nCtrl+C pour arrêter.\n`);
});
if (upd.auto) { setTimeout(() => checkUpdate(true), 60e3); setInterval(() => checkUpdate(true), 3600e3); }
