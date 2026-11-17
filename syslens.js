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

// Référentiel : referentiel.json (livré avec SysLens, l'ordre fait la priorité) + logs/ref-appris.json
// (types classés par l'IA puis validés par un technicien, et notes de base corrigées).
const REF_RAW = JSON.parse(fs.readFileSync(path.join(__dirname, 'referentiel.json'), 'utf8')).entries;
const mkRe = s => s ? new RegExp(s, 'i') : null;
const REF = REF_RAW.map(e => ({ ...e, cat: mkRe(e.cat), re: mkRe(e.re), priv: mkRe(e.priv) }));
// État des incidents décidé par un admin (acquitté, clos), partagé entre navigateurs : logs/incidents-etat.json
const INC_FILE = path.join(DIR, 'incidents-etat.json'), INC_KEEP = 400 * 864e5;
let incEtat = {}; try { incEtat = JSON.parse(fs.readFileSync(INC_FILE, 'utf8')) || {}; } catch (e) {}
function incApi(b, me) {
  if (!b || typeof b.key !== 'string' || !b.key || b.key.length > 300) throw new Error('Clé d’incident invalide.');
  if (!['ouvert', 'acquitté', 'clos'].includes(b.st)) throw new Error('Statut inconnu.');
  const snap = b.snap && typeof b.snap === 'object' ? Object.fromEntries(['sig', 'cli', 'cliName', 'dev', 'k', 's', 'lv', 'n', 'last'].filter(k => b.snap[k] !== undefined).map(k => [k, typeof b.snap[k] === 'number' ? b.snap[k] : String(b.snap[k]).slice(0, 200)])) : undefined;
  if (b.st === 'ouvert') delete incEtat[b.key]; else incEtat[b.key] = { st: b.st, t: Date.now(), ...(me ? { by: me.name } : {}), ...(snap ? { snap } : {}) };
  const lim = Date.now() - INC_KEEP; for (const [k, v] of Object.entries(incEtat)) if (v.t < lim) delete incEtat[k];
  const keys = Object.keys(incEtat); if (keys.length > 20000) keys.sort((a, c) => incEtat[a].t - incEtat[c].t).slice(0, keys.length - 20000).forEach(k => delete incEtat[k]);
  try { fs.writeFileSync(INC_FILE + '.tmp', JSON.stringify(incEtat)); fs.renameSync(INC_FILE + '.tmp', INC_FILE); } catch (e) { throw new Error('Écriture impossible : ' + e.message); }
  return { ok: true, etat: incEtat };
}
const LEARN_FILE = path.join(DIR, 'ref-appris.json'); let learned = { types: {}, bases: {}, decisions: [], auto: { on: false }, ia: null };
function loadLearned() { try { const j = JSON.parse(fs.readFileSync(LEARN_FILE, 'utf8')); learned = { types: j.types || {}, bases: j.bases || {}, decisions: Array.isArray(j.decisions) ? j.decisions : [], auto: j.auto || { on: false }, ia: j.ia || null }; } catch (e) {} }
loadLearned();
// Gabarit d'un message : les valeurs qui changent d'un log à l'autre sont remplacées, pour regrouper les logs d'un même type
// (et pour que ce qui part vers une IA ne contienne ni adresse, ni compte, ni nom de machine).
function tpl(s, ev) { let t = String(s || '');
  if (ev.user && ev.user.length > 2) t = t.split(ev.user).join('<user>'); if (ev.host && ev.host.length > 2) t = t.split(ev.host).join('<host>');
  return t.replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, '<mail>').replace(/\b[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}\b/gi, '<mac>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}(\/\d+|:\d+)?\b/g, '<ip>').replace(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|fr|io|eu|de|be|ch|uk|info|biz|local|lan|ru|cn|xyz|top)\b/gi, '<nom>')
    .replace(/\b0x[0-9a-f]+\b/gi, '#').replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().slice(0, 100); }
const catT = c => String(c || '?').replace(/\d+/g, '#').slice(0, 60);
const famOfProduct = p => /^(GS|XGS|XMG|XS|MS|MG)\d/i.test(p || '') ? 'switch' : /^(NWA|WAX|WAC|WBE|NAP)/i.test(p || '') ? 'borne Wi-Fi' : p ? 'pare-feu' : 'inconnu';
const shortHash = s => crypto.createHash('sha1').update(s).digest('hex').slice(0, 8);
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
  else { const i = rest.match(/^\s*(?:1\s)?(\d{4}-\d\d-\d\dT\S+)\s(\S+)\s([\s\S]*)$/); if (i) { ev.host = i[2].replace(/:$/, ''); rest = i[3]; } }   // horodatage ISO (switchs Zyxel, RFC 5424)
  const ci = rest.indexOf('CEF:');
  if (ci >= 0) {
    const c = rest.slice(ci + 4), parts = []; let cur = '', esc = false;
    for (const ch of c) { if (esc) { cur += ch; esc = false; } else if (ch === '\\') esc = true; else if (ch === '|' && parts.length < 7) { parts.push(cur); cur = ''; } else cur += ch; }
    parts.push(cur); ev.fmt = 'CEF'; ev.product = parts[2] || ''; ev.ver = parts[3] || ''; ev.name = parts[5] || '';
    // Une valeur peut contenir « = » (ex. « [type=Web Attack] » dans msg) : elle s'arrête au prochain « clé= » précédé d'un espace.
    const re = /(\w+)=([\s\S]*?)(?=\s+\w+=|$)/g; let x; while ((x = re.exec(parts[7] || ''))) ev.f[x[1]] = x[2].replace(/\\=/g, '=').trim();
    if (ev.f.ZYlevel && SEV.includes(ev.f.ZYlevel.toLowerCase())) ev.sev = SEV.indexOf(ev.f.ZYlevel.toLowerCase());
  } else {
    const re = /(\w+)="([^"]*)"/g; let x; while ((x = re.exec(rest))) ev.f[x[1]] = x[2];
    if (Object.keys(ev.f).length) ev.fmt = 'ZLD';
  }
  if (!ev.product && /^(XMG|XGS|XS|GS|MG)\d/i.test(ev.host)) ev.product = ev.host;
  // Syslog simple (switchs, bornes) : « authentication: HTTP(s) authentication failure… » → catégorie « authentication ».
  let tag = ''; if (ev.fmt === 'syslog') for (let i = 0; i < 2; i++) { const t = rest.match(/^\s*([A-Za-z][\w .\/()-]{0,30}?)(?:\[\d+\])?:\s+([\s\S]+)$/); if (!t) break; tag = t[1].trim(); rest = t[2];
    if (/^(NWA|WAX|WAC|WBE|NAP|GS|XGS|XMG|XS|MG|USG|ATP)\w*\d\w*$/i.test(tag)) { if (!ev.product) ev.product = tag; tag = ''; continue; } break; }   // « borne1 NWA110AX: wlan: … »
  ev.cat = ev.f.cat || ev.name || tag; ev.msg = ev.f.msg || ev.name || rest.trim();
  ev.src = ev.f.src || ''; ev.dst = ev.f.dst || ''; ev.user = ev.f.suser || ev.f.user || '';
  if (!ev.src) { const x = rest.match(/IP address\s*=\s*([\d.]+)|\bfrom\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)/i); if (x) ev.src = x[1] || x[2]; }
  if (!ev.user) { const x = rest.match(/user(?:name)?\s*[:=]\s*([^,\]\s]+)/i); if (x) ev.user = x[1]; }
  return ev;
}
const win = new Map();
// ctx = false : note de base seule (processus de réception) ; ctx = true : avec répétitions, horaires et force brute (processus principal).
function matchRef(ev, txt) { const out = isPublic(ev.dst) && !isPublic(ev.src), inb = isPublic(ev.src), priv = ev.f.spriv || ev.f.priv || '';
  return REF.find(r => (!r.cat || r.cat.test(ev.cat)) && (!r.re || r.re.test(txt)) && (!r.priv || r.priv.test(priv)) && (!r.when || (r.when === 'outbound' ? out : inb))); }
// Couverture d'un type : precis (règle du référentiel), appris (classé puis validé), categorie (catégorie connue, message pas encore détaillé),
// propose (l'IA a proposé une note, en attente), qualifier (inconnu, ou catégorie seule avec une gravité error ou plus).
// SYSLENS_EVAL=1 : banc d'essai de l'IA. Le référentiel ne note plus rien (tout passe « à qualifier ») mais sert de repère à l'IA,
// sans jamais lui montrer la règle qui correspond au log testé.
const EVAL = process.env.SYSLENS_EVAL === '1';
const refTxt = ev => (ev.fmt === 'syslog' && ev.cat ? ev.cat + ': ' : '') + ev.msg + ' ' + ev.name + ' ' + (ev.f.note || '') + ' ' + (ev.f.ZYnote || '');   // syslog simple : la catégorie est un mot du message
function score(ev, ctx = true) {
  const txt = refTxt(ev);
  const tk0 = catT(ev.cat) + ' | ' + tpl(ev.msg || ev.name, ev), L = learned.types[tk0], parts = [];
  const r = L && L.st === 'valide' ? { k: 'appris:' + shortHash(tk0), base: L.base, floor: L.floor || 0, telemetry: L.base < 30, learned: true } : EVAL ? null : matchRef(ev, txt);
  ev.k = r ? r.k : 'inconnu'; ev.ref = !!(r && !r.telemetry && !r.generic); ev.rec = !!(r && r.recovers);
  ev.tk = r && !r.generic && !r.learned ? catT(ev.cat) + ' | [' + r.k + ']' : tk0;
  ev.cov = !r ? 'qualifier' : r.learned ? 'appris' : r.generic ? (ev.sev <= 3 ? 'qualifier' : 'categorie') : 'precis';
  if (ev.cov === 'qualifier' && L && L.st === 'propose') ev.cov = 'propose';
  const fixed = learned.bases[ev.k];   // note de base corrigée par un technicien
  let s; if (!r || r.base == null) { s = BASE[ev.sev]; parts.push(['gravité ' + SEV[ev.sev] + ' annoncée par l’équipement', s]); }
  else { s = fixed != null ? fixed : r.base; parts.push([(r.learned ? 'type appris (validé)' : 'référentiel ' + r.k) + (fixed != null ? ', note corrigée' : ''), s]); }
  const add = (d, l) => { s += d; parts.push([l, d]); };
  if (ev.ref && /USG|ATP|FLEX|ZyWALL|VPN/i.test(ev.product)) add(10, 'pare-feu de tête');
  if (r && r.admin && isPublic(ev.src)) add(15, 'IP publique');
  if (ctx) {
    const key = ev.k + '|' + ev.dev + '|' + ev.src, now = ev.t; let arr = win.get(key); if (!arr) win.set(key, arr = []);
    while (arr.length && now - arr[0] >= 300e3) arr.shift(); arr.push(now); if (arr.length > 250) arr.splice(0, arr.length - 250);
    const n = arr.length, rep = n >= 200 ? 20 : n >= 50 ? 15 : n >= 10 ? 10 : n >= 3 ? 5 : 0; if (rep && ev.ref) add(rep, n + ' en 5 min');
    const hr = new Date(now).getHours(); if (r && r.admin && (hr < 8 || hr >= 19)) add(10, 'hors horaires');
    if (r && r.brute && n >= r.brute && s < 60) add(60 - s, 'force brute : ' + n + ' échecs en 5 min');
  }
  if (r && r.pubFloor && isPublic(ev.src) && s < r.pubFloor) add(r.pubFloor - s, 'admin depuis le WAN : critique');
  // Un type pas encore qualifié ne réveille pas l'astreinte : le niveau annoncé par l'équipement n'est pas assez fiable.
  if ((!r || r.generic) && s > 75) add(75 - s, 'type pas encore qualifié : grave au plus');
  // Proposition de l'IA en attente : elle peut monter la note (grave au plus), jamais la baisser avant validation.
  if ((!r || r.generic) && L && L.st === 'propose' && Math.min(75, L.base) > s) add(Math.min(75, L.base) - s, 'proposition de l’IA, à valider');
  const floor = r && r.floor || 0; if (s < floor) add(floor - s, 'plancher du référentiel');
  s = Math.min(100, Math.max(0, s)); ev.score = s; ev.level = level(s); ev.parts = parts;
  ev.why = parts.map(([l, d], i) => l + ' ' + (i && d >= 0 ? '+' : '') + d).join(' · ');
}
// Fenêtre de répétition : les sources silencieuses depuis 5 min sont oubliées (sinon les scans d'Internet la font grossir sans fin).
setInterval(() => { const lim = Date.now() - 300e3; for (const [k, a] of win) if (!a.length || a[a.length - 1] < lim) win.delete(k); if (win.size > 500000) win.clear(); }, 60e3).unref();
// --- réception : un ou plusieurs processus (WORKERS). Chaque processus lit, note et archive le brut ;
// seuls les événements utiles (référentiel ou gravité moyen et plus) et un échantillon des bénins remontent au processus principal.
// Un processus suffit jusqu'à plusieurs dizaines de milliers de logs/s ; WORKERS=n en ajoute pour les très gros parcs.
const WORKERS = Math.max(0, Math.min(32, +process.env.WORKERS || 0)), RAW_GZ = process.env.RAW_GZIP !== '0';
const RETENTION = Math.max(1, +process.env.RETENTION_DAYS || 90), SAMPLE = Math.max(0, +(process.env.SAMPLE ?? 20)), HIST_MAX = 50000;
const day = (d = new Date()) => d.toISOString().slice(0, 10);
const devKey = ev => ev.from + '|' + (ev.host || ev.f.devID || '');
// Écriture en flux, un fichier par jour ; le brut est compressé au fil de l'eau (gzip, environ 40 fois plus petit sur des logs Zyxel).
function dayWriter(name, gz) { let d = '', st = null, z = null;
  const w = line => { const t = day(); if (t !== d) { w.end(); d = t; st = fs.createWriteStream(path.join(DIR, name(t) + (gz ? '.gz' : '')), { flags: 'a' }); st.on('error', () => {});
    if (gz) { z = zlib.createGzip({ level: 1 }); z.on('error', () => {}); z.pipe(st); } } (z || st).write(line + '\n'); };
  w.end = () => { if (z) z.end(); else if (st) st.end(); z = st = null; };
  setInterval(() => { if (z) z.flush(); }, 5000).unref(); return w; }
const rawOut = dayWriter(t => 'raw-' + t + (cluster.isWorker ? '.w' + cluster.worker.id : '') + '.log', RAW_GZ);
const devDelta = new Map(), typeDelta = new Map(), ipDelta = new Map(); let rxCount = 0, budget = SAMPLE, outBuf = [];
setInterval(() => { budget = SAMPLE; }, 1000).unref();
function stage1(line, from) {
  line = line.replace(/\r?\n$/, ''); if (!line.trim()) return;
  rawOut(line); rxCount++;
  const ev = parse(line, from); ev.dev = devKey(ev); score(ev, false);
  let d = devDelta.get(ev.dev); if (!d) devDelta.set(ev.dev, d = { key: ev.dev, from, host: ev.host, product: ev.product, ver: ev.ver, fmt: ev.fmt, count: 0, first: ev.t, last: 0 });
  d.count++; d.last = ev.t; if (ev.product) { d.product = ev.product; d.ver = ev.ver; }
  // Adresse des équipements derrière un pare-feu, apprise de ses logs DHCP (« DHCP server assigned 192.168.1.34 to XMG1915(…) ») : sert au ping de vérification.
  if (/dhcp/i.test(ev.cat || '')) { const m = /assigned (\d{1,3}(?:\.\d{1,3}){3}) to ([\w.-]{2,64})\(/i.exec(ev.msg || ''); if (m && !isPublic(m[1])) ipDelta.set(m[2], { ip: m[1], t: ev.t }); }
  let ty = typeDelta.get(ev.tk);
  if (!ty) typeDelta.set(ev.tk, ty = { key: ev.tk, cat: ev.cat, msg: tpl(ev.msg || ev.name, ev), sev: SEV[ev.sev], k: ev.k, cov: ev.cov, fam: ev.product, count: 0, first: ev.t, example: line });
  ty.count++; ty.last = ev.t; if (ev.sev < SEV.indexOf(ty.sev)) ty.sev = SEV[ev.sev];
  const bk = Math.floor(ev.t / 300e3) * 300e3; let c = cntDelta.get(bk); if (!c) cntDelta.set(bk, c = { t: bk, n: 0, m: 0, g: 0, c: 0, fw: 0, sw: 0, ap: 0 });
  c.n++; if (ev.level !== 'benin') c[ev.level[0]]++; const fm = famOfProduct(ev.product); c[fm === 'switch' ? 'sw' : fm === 'borne Wi-Fi' ? 'ap' : 'fw']++;
  if (ev.ref || ev.rec || ev.level !== 'benin') emit(ev, false); else if (budget > 0) { budget--; emit(ev, true); }
}
const cntDelta = new Map();
function emit(ev, sample) { if (cluster.isWorker) outBuf.push([ev, sample]); else stage2(ev, sample); }
function statsPayload() { const p = { n: rxCount, devs: [...devDelta.values()], types: [...typeDelta.values()], counts: [...cntDelta.values()], ips: [...ipDelta] }; rxCount = 0; devDelta.clear(); typeDelta.clear(); cntDelta.clear(); ipDelta.clear(); return p; }
let udpBuf = 0;
function startReceivers(h) {
  const udp = dgram.createSocket('udp4');
  udp.on('message', (b, ri) => allowed(ri.address) ? h(b.toString('utf8'), ri.address) : drop(ri.address));
  // Tampon de réception UDP le plus grand que le système accepte : c'est lui qui absorbe les rafales (macOS plafonne vers 8 Mo,
  // Linux à net.core.rmem_max). Sans ça, on reste au tampon par défaut (≈ 200 Ko à 800 Ko) et les rafales sont perdues.
  udp.on('listening', () => { for (const mo of [32, 16, 8, 7, 6, 4, 2, 1]) { try { udp.setRecvBufferSize(mo << 20); break; } catch (e) {} }
    if (!cluster.isWorker || cluster.worker.id === 1) try { udpBuf = udp.getRecvBufferSize(); console.log(`Tampon UDP : ${(udpBuf / 1048576).toFixed(1)} Mo${udpBuf < 4 << 20 ? ' (petit : rafales perdues possibles, voir README › Capacité)' : ''}`); } catch (e) {} });
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
  process.on('message', m => { if (m && m.t === 'learned') loadLearned(); });   // référentiel appris modifié dans la console
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
  if (ev.level !== 'benin') incident(ev); else if (ev.rec) recover(ev);
  if (!replay) console.log(`${new Date(ev.t).toLocaleTimeString('fr-FR')} ${ev.from.padEnd(15)} ${COL[ev.level]}${ev.level.toUpperCase().padEnd(8)}${RST} ${String(ev.score).padStart(3)}  ${(ev.cat || '-').slice(0, 22).padEnd(22)} ${ev.msg.slice(0, 90)}`);
}
// Incidents agrégés côté serveur : un par (type, équipement, source), gardés 7 jours après le dernier événement.
function incident(ev) {
  const ik = ev.cov === 'precis' || ev.cov === 'appris' ? ev.k : ev.tk, key = ik + '|' + ev.dev + '|' + ev.src; let I = incidents.get(key);
  if (I) incidents.delete(key); else I = { key, k: ev.k, tk: ev.tk, dev: ev.dev, from: ev.from, host: ev.host, product: ev.product, src: ev.src, cat: ev.cat, first: ev.t, count: 0, score: 0, level: 'benin', samples: [] };
  I.count++; I.last = ev.t; I.msg = ev.msg; I.why = ev.why; I.status = 'ouvert'; I.resolved = null; if (ev.score >= I.score) { I.score = ev.score; I.level = ev.level; }
  const tk = portTok(ev.msg); if (tk) { I.toks = I.toks || []; if (!I.toks.includes(tk)) I.toks.push(tk); }
  I.samples.push(ev.raw); if (I.samples.length > 5) I.samples.shift(); incidents.set(key, I);
  if (incidents.size > 50000) incidents.delete(incidents.keys().next().value);
}
setInterval(() => { const lim = Date.now() - 7 * 864e5; for (const [k, I] of incidents) if (I.last < lim) incidents.delete(k); }, 600e3).unref();
// « Port 3 is down » puis « Port 3 is up » : l'incident est marqué résolu tout seul (il se rouvre si le lien retombe).
const portTok = m => { const x = String(m || '').match(/\b(port\s*\d+|lan\d+|wan\d*|ge\d+|opt\d*|eth\d+)\b/i); return x ? x[1].toLowerCase().replace(/\s+/g, '') : ''; };
function recover(ev) { const r = REF.find(x => x.k === ev.k), tk = portTok(ev.msg);
  for (const I of incidents.values()) if (I.dev === ev.dev && r && r.recovers.includes(I.k) && I.status !== 'résolu' && I.last <= ev.t && (!tk || !I.toks || I.toks.includes(tk))) {
    I.status = 'résolu'; I.resolved = ev.t; I.resolvedBy = ev.msg; } }
// Un switch ou une borne n'envoie de log que s'il se passe quelque chose : avant de le dire silencieux, on le pinge.
// Adresse : apprise des logs DHCP du pare-feu, ou sa source syslog si elle est privée et n'est partagée avec aucun autre équipement (pas de NAT).
const IP_FILE = path.join(DIR, 'adresses.json'), hostIp = new Map(); let ipDirty = false;
const QUIET_MS = Math.max(0.02, +process.env.SYSLENS_QUIET_MIN || 10) * 60e3;   // silence au-delà de laquelle on pinge
try { for (const [h, v] of Object.entries(JSON.parse(fs.readFileSync(IP_FILE, 'utf8')))) hostIp.set(h, v); } catch (e) {}
const PRIV = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}(\.\d{1,3})?$/.test(ip) && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
function ping(ip) { return new Promise(ok => { if (!PRIV(ip)) return ok({ ok: false, ms: null });
  const a = process.platform === 'win32' ? ['-n', '1', '-w', '2000', ip] : process.platform === 'darwin' ? ['-c', '1', '-t', '2', ip] : ['-c', '1', '-W', '2', ip];
  cp.execFile('ping', a, { timeout: 4000, windowsHide: true }, (err, out) => { const m = /time[=<]\s*([\d.]+)\s*ms/i.exec(String(out || '')); ok({ ok: !err && !!m, ms: m ? +m[1] : null }); }); }); }
async function checkQuiet() {
  const now = Date.now(), byFrom = new Map(); for (const d of devices.values()) byFrom.set(d.from, (byFrom.get(d.from) || 0) + 1);
  for (const d of [...devices.values()].slice(0, 500)) { const fam = famOfProduct(d.product || d.host);
    if (fam === 'pare-feu' || now - (d.last || 0) < QUIET_MS) { d.ping = undefined; continue; }
    const learned = d.host && hostIp.get(d.host), ip = learned ? learned.ip : PRIV(d.from) && byFrom.get(d.from) === 1 ? d.from : null;
    if (!ip) { d.ping = { ip: null, ok: false, t: now }; continue; }
    const r = await ping(ip); d.ping = { ip, ok: r.ok, ms: r.ms, t: Date.now() }; }
  if (ipDirty) { ipDirty = false; try { fs.writeFileSync(IP_FILE, JSON.stringify(Object.fromEntries(hostIp))); } catch (e) {} } }
if (!SELFTEST) setInterval(() => checkQuiet().catch(() => {}), Math.min(60e3, Math.max(2e3, QUIET_MS))).unref();
function mergeStats(p) {
  total += p.n; rate += p.n;
  for (const x of p.counts || []) { const c = counts.get(x.t); if (!c) counts.set(x.t, { ...x }); else for (const k of CNT_K) c[k] += x[k]; countsDirty = true; }
  for (const [h, v] of p.ips || []) { hostIp.set(h, v); ipDirty = true; }
  for (const x of p.devs) { let d = devices.get(x.key);
    if (!d) { d = { ...x, count: 0 }; devices.set(x.key, d); console.log(`\n\x1b[32m✓ Premier log reçu de ${x.from}${x.host ? ' (' + x.host + ')' : ''}${x.product ? ' : ' + x.product + ' ' + x.ver : ''} (format ${x.fmt})\x1b[0m\n`); }
    d.count += x.count; d.last = Math.max(d.last || 0, x.last); if (x.product) { d.product = x.product; d.ver = x.ver; } }
  for (const x of p.types) { let ty = types.get(x.key);
    if (!ty) { if (types.size >= TYPES_MAX) { let lo = null; for (const t of types.values()) if (!lo || t.count < lo.count) lo = t; types.delete(lo.key); } types.set(x.key, ty = { ...x, count: 0 }); }
    ty.count += x.count; ty.last = Math.max(ty.last || 0, x.last || 0); ty.k = x.k; ty.cov = x.cov; if (SEV.indexOf(x.sev) < SEV.indexOf(ty.sev)) ty.sev = x.sev; if (x.fam) ty.fam = x.fam; typesDirty = true; }
}
let lastRate = 0; setInterval(() => { lastRate = Math.round(rate / 10); rate = 0; }, 10e3).unref();
setInterval(() => { if (!WORKERS) mergeStats(statsPayload()); }, 1000).unref();
// types.json : tous les types de logs vus depuis l'installation (cumulé, gardé d'un redémarrage à l'autre).
const TYPES_FILE = path.join(DIR, 'types.json'), TYPES_MAX = 5000; let typesDirty = false;
try { for (const t of JSON.parse(fs.readFileSync(TYPES_FILE, 'utf8'))) if (t && t.key && /\| /.test(t.key) && t.cov) types.set(t.key, t); } catch (e) {}
const saveTypes = () => { if (!typesDirty) return; typesDirty = false; const tmp = TYPES_FILE + '.part';
  fs.writeFile(tmp, JSON.stringify([...types.values()].sort((a, b) => b.count - a.count), null, 1), err => { if (!err) fs.rename(tmp, TYPES_FILE, () => {}); }); };
setInterval(saveTypes, 15e3).unref();
// Compteurs par tranche de 5 min (tous les logs reçus, bénins compris) : gardés 7 jours, relus au démarrage.
const COUNTS_FILE = path.join(DIR, 'compteurs.json'), CNT_K = ['n', 'm', 'g', 'c', 'fw', 'sw', 'ap'], counts = new Map(); let countsDirty = false;
try { for (const c of JSON.parse(fs.readFileSync(COUNTS_FILE, 'utf8'))) if (c && Number.isFinite(c.t)) counts.set(c.t, c); } catch (e) {}
const saveCounts = sync => { if (!countsDirty) return; countsDirty = false; const lim = Date.now() - 7 * 864e5; for (const t of counts.keys()) if (t < lim) counts.delete(t);
  const tmp = COUNTS_FILE + '.part', data = JSON.stringify([...counts.values()].sort((a, b) => a.t - b.t));
  if (sync) { try { fs.writeFileSync(tmp, data); fs.renameSync(tmp, COUNTS_FILE); } catch (e) {} } else fs.writeFile(tmp, data, err => { if (!err) fs.rename(tmp, COUNTS_FILE, () => {}); }); };
setInterval(saveCounts, 60e3).unref();
// Archives : les jours passés sont compressés, au-delà de RETENTION_DAYS (90 par défaut) ils sont supprimés.
function maintain() { const today = day(), lim = new Date(Date.now() - RETENTION * 864e5).toISOString().slice(0, 10);
  let names = []; try { names = fs.readdirSync(DIR); } catch (e) { return; }
  for (const f of names) { const m = /^(?:raw|events)-(\d{4}-\d{2}-\d{2})(?:\.w\d+)?\.(?:log|jsonl)(\.gz)?$/.exec(f); if (!m) continue; const p = path.join(DIR, f);
    if (m[1] < lim) { fs.rmSync(p, { force: true }); continue; }
    if (m[1] < today && !m[2]) { try { if (Date.now() - fs.statSync(p).mtimeMs < 600e3) continue; } catch (e) { continue; }
      const tmp = p + '.gz.part'; require('stream').pipeline(fs.createReadStream(p), zlib.createGzip(), fs.createWriteStream(tmp), err => { if (err) return fs.rmSync(tmp, { force: true });
        try { if (fs.existsSync(p + '.gz')) { fs.appendFileSync(p + '.gz', fs.readFileSync(tmp)); fs.rmSync(tmp, { force: true }); } else fs.renameSync(tmp, p + '.gz'); fs.rmSync(p, { force: true }); } catch (e) { console.error('Archive ' + f + ' : ' + e.message); } }); } } }
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
{ // Les fichiers d'événements ne gardent que les événements utiles (avec leur ligne brute) : rechargement rapide même à fort débit.
  const since = Date.now() - 24 * 3600e3, rebuild = !counts.size, readDay = d => { const f = path.join(DIR, 'events-' + d + '.jsonl');
    try { return fs.readFileSync(f, 'utf8'); } catch (e) { try { return zlib.gunzipSync(fs.readFileSync(f + '.gz')).toString('utf8'); } catch (x) { return ''; } } };
  const lines = [day(new Date(since)), day()].filter((d, i, a) => a.indexOf(d) === i).flatMap(d => readDay(d).split('\n'));
  for (const l of lines) { if (!l) continue; let e; try { e = JSON.parse(l); } catch (x) { continue; }
    if (!e.t || e.t < since || !allowed(e.from)) continue;
    if (e.raw) { const t = e.t; e = parse(e.raw, e.from); e.t = t; } else { e.raw = ''; e.f = e.f || {}; e.msg = e.msg || ''; e.name = e.name || ''; e.cat = e.cat || ''; }
    e.dev = devKey(e); score(e, false); stage2(e, false, true);
    if (rebuild) { const bk = Math.floor(e.t / 300e3) * 300e3; let c = counts.get(bk); if (!c) counts.set(bk, c = { t: bk, n: 0, m: 0, g: 0, c: 0, fw: 0, sw: 0, ap: 0 });   // première fois : compteurs tirés des événements gardés
      c.n++; if (e.level !== 'benin') c[e.level[0]]++; const fm = famOfProduct(e.product); c[fm === 'switch' ? 'sw' : fm === 'borne Wi-Fi' ? 'ap' : 'fw']++; countsDirty = true; }
    let d = devices.get(e.dev); if (!d) devices.set(e.dev, d = { key: e.dev, from: e.from, host: e.host, product: e.product, ver: e.ver, fmt: e.fmt, first: e.t, count: 0 }); d.last = e.t; d.count++; }
  if (hist.length) console.log('Dernières 24 h rechargées : ' + hist.length + ' événements utiles');
}
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
// --- IA : question ponctuelle au modèle configuré dans la console (clé envoyée par la console à chaque appel, jamais écrite sur disque)
const AI_CHAT = { chatgpt: 'https://api.openai.com/v1/chat/completions', mistral: 'https://api.mistral.ai/v1/chat/completions', grok: 'https://api.x.ai/v1/chat/completions', hermes: 'https://inference-api.nousresearch.com/v1/chat/completions' };
const SUB_TOOL = { chatgpt: 'codex', claude: 'claudecode', gemini: 'geminicli' };
const aiStats = { last: null };
async function aiAsk(c, prompt, schema, maxTok = 4000, json = true) {
  const msgs = Array.isArray(prompt) ? prompt : [{ role: 'user', content: prompt }], flat = msgs.map(m => (m.role === 'system' ? '' : m.role === 'user' ? 'Utilisateur : ' : 'Assistant : ') + m.content).join('\n\n');
  const ms = Math.max(30, Math.min(600, +c.timeout || 180)) * 1000, signal = AbortSignal.timeout(ms), model = String(c.model || '').trim();
  const post = async (url, headers, body) => { const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal }).catch(e => { throw new Error(e.name === 'TimeoutError' ? 'Le modèle n’a pas répondu à temps.' : 'Le fournisseur ne répond pas.'); });
    const j = await r.json().catch(() => ({})); if (r.status === 401 || r.status === 403) throw new Error('Clé refusée par le fournisseur.'); if (!r.ok) throw new Error('Le fournisseur a répondu ' + r.status + (j.error && j.error.message ? ' : ' + String(j.error.message).slice(0, 200) : '') + '.'); return j; };
  if (c.mode === 'sub') { const id = SUB_TOOL[c.prov], t = CLI[id]; if (!t) throw new Error('Pas d’abonnement pour ce fournisseur.');
    const args = id === 'codex' ? ['exec', '--skip-git-repo-check', ...(model ? ['-m', model] : []), '-'] : id === 'claudecode' ? ['-p', ...(model ? ['--model', model] : [])] : ['-p', 'Réponds à la demande ci-dessus.', ...(model ? ['-m', model] : [])];
    fs.mkdirSync(OUTILS, { recursive: true });
    return new Promise((ok, ko) => { const p = cp.spawn(cliBin(t), args, { env: cliEnv(t), cwd: OUTILS, shell: WIN }); let out = '', err = '';
      const k = setTimeout(() => { p.kill(); ko(new Error('Le modèle n’a pas répondu à temps.')); }, ms);
      p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { err += d; }); p.on('error', e => { clearTimeout(k); ko(new Error(t.bin + ' : ' + e.message)); });
      p.on('close', code => { clearTimeout(k); code === 0 ? ok(strip(out)) : ko(new Error(t.bin + ' a échoué : ' + strip(err || out).trim().split('\n').pop().slice(0, 200))); });
      p.stdin.end(flat); }); }
  if (!model) throw new Error('Aucun modèle choisi.');
  if (c.mode === 'local' || c.prov === 'ollama') { let u; try { u = new URL('/api/chat', String(c.url || '')); } catch (e) { throw new Error('Adresse Ollama invalide.'); }
    // think: false : les modèles « qui réfléchissent » (qwen3…) répondent directement, 5 à 10 fois plus vite ; le modèle reste chargé 30 min entre deux lots.
    // Schéma JSON imposé et longueur bornée : en simple mode « json », un modèle peut écrire des blancs sans fin jusqu'à remplir son contexte.
    const j = await post(u, {}, { model, stream: false, think: false, keep_alive: '30m', ...(json ? { format: schema || 'json' } : {}), options: { temperature: json ? 0.1 : 0.3, num_ctx: 8192, num_predict: maxTok }, messages: msgs });
    if (j.eval_count && j.eval_duration) aiStats.last = { tokens: j.eval_count, tps: Math.round(j.eval_count / (j.eval_duration / 1e9)), ms: Math.round((j.total_duration || 0) / 1e6) };
    return (j.message && j.message.content) || ''; }
  const key = String(c.key || '').trim(); if (key.length < 20 || /\s/.test(key)) throw new Error('Clé API absente : saisissez-la de nouveau dans Paramètres › Intelligence artificielle.');
  if (AI_CHAT[c.prov]) { const j = await post(AI_CHAT[c.prov], { authorization: 'Bearer ' + key }, { model, messages: msgs }); return ((j.choices || [])[0] || {}).message?.content || ''; }
  if (c.prov === 'claude') { const j = await post('https://api.anthropic.com/v1/messages', { 'x-api-key': key, 'anthropic-version': '2023-06-01' }, { model, max_tokens: 8000, ...(msgs[0].role === 'system' ? { system: msgs[0].content } : {}), messages: msgs.filter(m => m.role !== 'system') }); return (j.content || []).map(x => x.text || '').join(''); }
  if (c.prov === 'gemini') { const j = await post('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model.replace(/^models\//, '')) + ':generateContent', { 'x-goog-api-key': key }, { ...(msgs[0].role === 'system' ? { systemInstruction: { parts: [{ text: msgs[0].content }] } } : {}), contents: msgs.filter(m => m.role !== 'system').map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })) });
    return (((j.candidates || [])[0] || {}).content || { parts: [] }).parts.map(x => x.text || '').join(''); }
  throw new Error('Fournisseur inconnu.'); }
// --- types à qualifier : classés par l'IA (proposition), puis validés ou corrigés par un technicien
function saveLearned() { const tmp = LEARN_FILE + '.part'; fs.writeFileSync(tmp, JSON.stringify(learned, null, 1), { mode: 0o600 }); fs.renameSync(tmp, LEARN_FILE);
  for (const w of Object.values(cluster.workers || {})) try { w.send({ t: 'learned' }); } catch (e) {}
  for (const ty of types.values()) { const L = learned.types[ty.key]; if (L && L.st === 'valide') ty.cov = 'appris'; else if (L && L.st === 'propose' && ty.cov === 'qualifier') ty.cov = 'propose'; else if (!L && (ty.cov === 'propose' || ty.cov === 'appris')) ty.cov = 'qualifier'; } typesDirty = true; }
const queue = () => [...types.values()].filter(t => t.cov === 'qualifier' && !learned.types[t.key]).sort((a, b) => b.count - a.count);
let classifying = null;
// Apprentissage : chaque validation ou correction d'un technicien est gardée (decisions) et sert d'exemple aux lots suivants.
// Autonomie (option) : quand l'IA est d'accord avec les techniciens au moins AUTO_RATE fois sur AUTO_WIN décisions récentes,
// ses propositions sûres d'elles sont validées seules. Jamais pour baisser sous 30 un log que l'équipement annonce alert ou pire.
const AUTO_WIN = 20, AUTO_MIN = 10, AUTO_RATE = 0.9, AUTO_CONF = 0.7, LEVEL = b => b >= 85 ? 3 : b >= 60 ? 2 : b >= 30 ? 1 : 0;
const agree = d => Math.abs(d.prop - d.final) <= 10 && LEVEL(d.prop) === LEVEL(d.final);
function learnStats() { const d = learned.decisions.filter(x => !x.auto), rec = d.slice(-AUTO_WIN), ok = rec.filter(agree).length;
  return { decisions: d.length, recent: rec.length, agree: ok, rate: rec.length ? ok / rec.length : 0, ready: rec.length >= AUTO_MIN && ok / rec.length >= AUTO_RATE,
    autoOn: !!(learned.auto && learned.auto.on), autoCount: learned.decisions.filter(x => x.auto).length, ia: learned.ia, lastCall: aiStats.last }; }
// Exemples choisis par ressemblance : pour chaque type à noter, les types validés qui partagent le plus de mots
// (catégorie + message), puis les plus récents pour compléter. Un modèle de 8 milliards de paramètres apprend surtout par analogie.
const STOP = new Set('the and for from with has have been was are not this that has to of in on by is at as an or de la le les des du un une et en est pour par sur au'.split(' '));
const words = t => new Set(String((t.cat || '') + ' ' + (t.msg || '')).toLowerCase().replace(/<\w+>|#/g, ' ').split(/[^a-z0-9àâçéèêëîïôûùüÿ]+/).filter(w => w.length > 2 && !STOP.has(w)));
function examples(list, n = 12) {
  const val = Object.entries(learned.types).filter(([, v]) => v.st === 'valide' && v.msg).sort((a, b) => (b[1].at || 0) - (a[1].at || 0)).slice(0, 1500).map(e => [e, words(e[1])]), pick = [];
  for (const t of list) { const w = words(t), scored = [];
    for (const [e, ew] of val) { let k = 0; for (const x of w) if (ew.has(x)) k++; if (k) scored.push([k / Math.sqrt(ew.size * w.size || 1) + (e[1].cat === t.cat ? 0.5 : 0), e]); }
    scored.sort((a, b) => b[0] - a[0]); for (const [, e] of scored.slice(0, 2)) if (!pick.includes(e) && pick.length < n) pick.push(e); }
  for (const [e] of val) if (pick.length < n && !pick.includes(e)) pick.push(e);
  return pick.map(([, v]) => ({ categorie: v.cat || '', message: v.msg, base: v.base, sig: v.sig, ...(v.prop != null && Math.abs(v.prop - v.base) > 10 ? { note: `l’IA avait proposé ${v.prop}, le technicien a corrigé` } : {}) })); }
async function classify(c, max, opts = {}) {
  const list = queue().slice(0, Math.max(1, Math.min(40, +max || 25))); if (!list.length) return { proposed: 0, left: 0 };
  const items = list.map((t, i) => ({ id: i + 1, categorie: t.cat || '', message: t.msg || '', gravite_equipement: t.sev, equipement: famOfProduct(t.fam), vu: t.count }));
  const ex = opts.exemples === false ? [] : examples(list);
  // Repères : le barème du centre (référentiel livré, notes corrigées comprises), sauf la règle qui décrirait déjà un type du lot.
  const cache = new Set(); if (opts.reperes !== false) for (const t of list) try { const ev = parse(t.example || '', '127.0.0.1'); const r = ev && matchRef(ev, refTxt(ev)); if (r) cache.add(r.k); } catch (e) {}
  // Les ~30 repères les plus proches des types du lot (mots de leur catégorie et de leur motif), pour garder une consigne courte.
  const lw = new Set(list.flatMap(t => [...words(t)])), anc = REF_RAW.filter(e => e.base != null && !e.generic && !e.k.startsWith('cat-') && !cache.has(e.k))
    .map(e => { const w = String((e.cat || '') + ' ' + (e.re || '')).toLowerCase().split(/[^a-z0-9]+/).filter(x => x.length > 2); let k = 0; for (const x of new Set(w)) if (lw.has(x)) k++; return [k, e]; })
    .sort((x, y) => y[0] - x[0]);
  const rep = opts.reperes === false ? [] : anc.slice(0, 30).map(([, e]) => `${e.sig} (${e.fam}) : ${learned.bases[e.k] ?? e.base}`);
  const prompt = `Tu aides un centre de supervision qui surveille des équipements Zyxel (pare-feu ZLD et uOS, switchs, bornes Wi-Fi) chez des clients.
Pour chaque type de log ci-dessous, propose une note de gravité de base de 0 à 100 :
- 85 à 100, critique : action immédiate (malware actif, administrateur connecté depuis Internet, panne totale du site)
- 60 à 84, grave : à traiter dans la journée (lien ou VPN tombé, attaque en cours, matériel en défaut)
- 30 à 59, moyen : à surveiller (changement de configuration, échecs isolés, ressource qui sature)
- 0 à 29, bénin : routine, relevés périodiques, fonctionnement normal
Les valeurs variables ont été remplacées : <ip>, <mac>, <user>, <host>, <nom>, <mail>, # pour les nombres.
Réponds uniquement par un objet JSON, sans texte autour :
{"types":[{"id":1,"base":0,"sig":"nom court en français (60 caractères au plus)","mean":"ce que ce log veut dire, une phrase","act":"ce que le technicien doit faire, une phrase","confiance":0.0}]}
Si tu ne connais pas ce message, mets une confiance inférieure à 0.5 et une note prudente.${rep.length ? `
Barème du centre : types déjà connus et la note qu’on leur donne. Note les nouveaux types de façon cohérente avec ce barème.
${rep.join('\n')}` : ''}${ex.length ? `
Voici des types déjà notés par les techniciens de ce centre. Ils font foi : aligne tes notes sur leur façon de juger (même catégorie ou même nature de message → note proche).
${JSON.stringify(ex, null, 1)}` : ''}
Types à noter :
${JSON.stringify(items, null, 1)}`;
  const SCHEMA = { type: 'object', required: ['types'], properties: { types: { type: 'array', items: { type: 'object', required: ['id', 'base', 'sig', 'mean', 'act', 'confiance'],
    properties: { id: { type: 'integer' }, base: { type: 'integer' }, sig: { type: 'string' }, mean: { type: 'string' }, act: { type: 'string' }, confiance: { type: 'number' } } } } } };
  const out = await aiAsk(c, prompt, SCHEMA, 250 * list.length + 300), a = out.indexOf('{'), b = out.lastIndexOf('}'); let j;
  try { j = JSON.parse(out.slice(a, b + 1)); } catch (e) { throw new Error('Réponse de l’IA illisible (pas de JSON).'); }
  const src = 'IA ' + String(c.prov || '') + (c.model ? ' ' + String(c.model).slice(0, 60) : '') + ', ' + new Date().toISOString().slice(0, 10); let n = 0;
  const st = learnStats(), auto = st.autoOn && st.ready; let na = 0;
  for (const x of Array.isArray(j.types) ? j.types : []) { const t = list[(+x.id || 0) - 1]; if (!t || !Number.isFinite(+x.base) || learned.types[t.key]) continue;
    const base = Math.round(Math.max(0, Math.min(100, +x.base))), conf = Math.max(0, Math.min(1, +x.confiance || 0));
    const sure = auto && conf >= AUTO_CONF && !(base < 30 && /^(alert|crit|emerg)/i.test(t.sev || ''));
    learned.types[t.key] = { st: sure ? 'valide' : 'propose', base, prop: base, sig: String(x.sig || t.msg).slice(0, 80), mean: String(x.mean || '').slice(0, 300), act: String(x.act || '').slice(0, 300),
      conf, src: sure ? src + ', validé seul (autonomie)' : src, auto: sure || undefined, at: Date.now(), cat: t.cat, msg: t.msg, sev: t.sev };
    if (sure) { learned.decisions.push({ key: t.key, prop: base, final: base, auto: true, at: Date.now() }); na++; } n++; }
  if (learned.decisions.length > 2000) learned.decisions = learned.decisions.slice(-2000);
  if (n) saveLearned(); console.log(`\x1b[36mIA : ${n} type(s) de log classé(s)${na ? `, dont ${na} validé(s) seul(s)` : ''}${ex.length ? ` (${ex.length} exemples appris)` : ''}\x1b[0m`);
  return { proposed: n, auto: na, examples: ex.length, left: queue().length, call: aiStats.last }; }
// Classement en continu côté serveur, sans console ouverte : seulement une IA locale (Ollama), donc sans clé à garder.
setInterval(() => { if (learned.ia && !classifying && queue().length) { classifying = classify(learned.ia, 12).catch(e => console.log('IA : ' + e.message)).finally(() => { classifying = null; }); } }, 120e3).unref();
async function refApi(q, me) {
  const num = v => v === null || v === '' || v === undefined ? null : Math.round(Math.max(0, Math.min(100, +v)));
  if (q.op === 'classify') { if (classifying) throw new Error('Un classement est déjà en cours.'); classifying = classify(q.ai || {}, q.max, { exemples: q.exemples, reperes: q.reperes }).finally(() => { classifying = null; }); return classifying; }
  if (q.op === 'auto') { learned.auto = { on: !!q.on }; saveLearned(); return { ok: true, stats: learnStats() }; }
  if (q.op === 'ia') { if (!q.ai) { learned.ia = null; saveLearned(); return { ok: true }; }
    const a = q.ai, u = new URL(String(a.url || 'http://127.0.0.1:11434')); if (!/^https?:$/.test(u.protocol) || !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)) throw new Error('Classement en continu : IA locale (Ollama sur ce poste) seulement.');
    if (!/^[\w.:/-]{1,80}$/.test(String(a.model || ''))) throw new Error('Modèle invalide.'); learned.ia = { prov: 'ollama', mode: 'local', url: u.origin, model: String(a.model) }; saveLearned(); return { ok: true }; }
  if (q.op === 'base') { const k = String(q.k || ''); if (!REF.some(r => r.k === k)) throw new Error('Entrée inconnue.'); const b = num(q.base); if (b === null) delete learned.bases[k]; else learned.bases[k] = b; saveLearned(); return { ok: true }; }
  const key = String(q.key || ''), t = types.get(key), L = learned.types[key]; if (!t && !L) throw new Error('Type inconnu.');
  if (q.op === 'valide' || q.op === 'manuel') { const b = num(q.base != null ? q.base : L && L.base); if (b === null || !Number.isFinite(b)) throw new Error('Note invalide.');
    if (L && L.st === 'propose' && Number.isFinite(L.base)) learned.decisions.push({ key, prop: L.base, final: b, at: Date.now(), ...(me ? { by: me.name } : {}) });
    learned.types[key] = { ...(L || {}), st: 'valide', base: b, sig: String(q.sig || (L && L.sig) || (t && t.msg) || key).slice(0, 80), mean: String(q.mean || (L && L.mean) || '').slice(0, 300), act: String(q.act || (L && L.act) || '').slice(0, 300),
      src: q.op === 'manuel' ? 'Classé par ' + (me ? me.name : 'un technicien') + ', ' + new Date().toISOString().slice(0, 10) : ((L && L.src) || 'IA') + ', validé' + (me ? ' par ' + me.name : ''), at: Date.now(), cat: (t && t.cat) || (L && L.cat), msg: (t && t.msg) || (L && L.msg) };
    saveLearned(); return { ok: true }; }
  if (q.op === 'rejet') { if (L) { if (L.st === 'propose') learned.decisions.push({ key, prop: L.base, final: -100, at: Date.now() }); L.st = 'rejete'; L.at = Date.now(); saveLearned(); } return { ok: true }; }
  if (q.op === 'oublier') { delete learned.types[key]; saveLearned(); return { ok: true }; }
  throw new Error('Opération inconnue.'); }
function refPayload() { const tys = [...types.values()].sort((a, b) => b.count - a.count), cov = {};
  for (const t of tys) cov[t.cov] = (cov[t.cov] || 0) + t.count;
  return { entries: REF_RAW, bases: learned.bases, learned: Object.entries(learned.types).map(([key, v]) => ({ key, k: 'appris:' + shortHash(key), ...v })),
    types: tys.slice(0, 3000), coverage: cov, queue: queue().length, classifying: !!classifying, learn: learnStats() }; }
const sameOrigin = q => { const o = q.headers.origin; return (!o || /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(o)) && /application\/json/.test(q.headers['content-type'] || ''); };
// ---------- Comptes et sessions ----------
// Tant qu'aucun compte n'existe, la console reste ouverte (installation, essais). Dès que le premier compte est créé
// (depuis ce poste uniquement), il est administrateur et toute la console demande une connexion.
const ACC_FILE = path.join(DIR, 'comptes.json'), SESS_FILE = path.join(DIR, 'sessions.json'), CHAT_DIR = path.join(DIR, 'conversations'), SESS_MS = 12 * 3600e3;
let accounts = { users: {} }; try { accounts = JSON.parse(fs.readFileSync(ACC_FILE, 'utf8')); if (!accounts.users) accounts.users = {}; } catch (e) {}
let sessions = {}; try { sessions = JSON.parse(fs.readFileSync(SESS_FILE, 'utf8')) || {}; } catch (e) {}
const writeSecret = (f, o) => { fs.writeFileSync(f + '.part', JSON.stringify(o, null, 1), { mode: 0o600 }); fs.renameSync(f + '.part', f); };
const saveAcc = () => writeSecret(ACC_FILE, accounts);
const saveSess = () => { const now = Date.now(); for (const [k, v] of Object.entries(sessions)) if (v.exp < now || !accounts.users[v.uid]) delete sessions[k]; try { writeSecret(SESS_FILE, sessions); } catch (e) {} };
const hasAccounts = () => Object.keys(accounts.users).length > 0;
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 << 20 };
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 64, SCRYPT).toString('hex') });
const checkPw = (u, pw) => crypto.timingSafeEqual(crypto.scryptSync(String(pw), u.salt, 64, SCRYPT), Buffer.from(u.hash, 'hex'));
function pwCheck(pw) { if (typeof pw !== 'string' || pw.length < 10 || pw.length > 200) throw new Error('Mot de passe : 10 caractères au moins.'); return pw; }
function loginCheck(l) { l = String(l || '').trim().toLowerCase(); if (!/^[a-z0-9._-]{2,32}$/.test(l)) throw new Error('Identifiant : 2 à 32 caractères (lettres, chiffres, . _ -).'); return l; }
const nameCheck = n => { n = String(n || '').trim().replace(/\s+/g, ' '); if (n.length < 2 || n.length > 60) throw new Error('Nom : 2 à 60 caractères.'); return n; };
const cookieTok = q => { const m = /(?:^|;\s*)sl_sess=([a-f0-9]{64})/.exec(q.headers.cookie || ''); return m && m[1]; };
function who(q) { const t = cookieTok(q); if (!t) return null; const s = sessions[sha(t)]; if (!s || s.exp < Date.now()) return null; const u = accounts.users[s.uid];
  return u ? { id: s.uid, login: u.login, name: u.name, role: u.role } : null; }
const isLoop = q => /^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$/.test(q.socket.remoteAddress || '');
const pubUser = (id, u) => ({ id, login: u.login, name: u.name, role: u.role, created: u.created });
function newSession(r, uid) { const t = crypto.randomBytes(32).toString('hex'); sessions[sha(t)] = { uid, exp: Date.now() + SESS_MS }; saveSess();
  r.setHeader('set-cookie', `sl_sess=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESS_MS / 1000}`); }
const send = (r, code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
const readBody = (q, max) => new Promise((ok, ko) => { let b = ''; q.on('data', d => { b += d; if (b.length > max) { ko(new Error('Requête trop longue.')); q.destroy(); } });
  q.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch (e) { ko(new Error('Requête illisible.')); } }); });
const fails = new Map();
async function authApi(q, r, me, url) {
  if (url === '/api/auth/moi') return send(r, 200, { user: me && { ...me, mustChange: !!accounts.users[me.id].mustChange }, setup: !hasAccounts() });
  if (q.method !== 'POST' || !sameOrigin(q)) return send(r, 403, { error: 'Refusé.' });
  const b = await readBody(q, 4096);
  if (url === '/api/auth/setup') { if (hasAccounts()) return send(r, 409, { error: 'Le compte administrateur existe déjà : connectez-vous.' });
    if (!isLoop(q)) return send(r, 403, { error: 'Le premier compte se crée depuis le poste où tourne SysLens.' });
    const id = crypto.randomUUID(); accounts.users[id] = { login: loginCheck(b.login), name: nameCheck(b.name), role: 'admin', ...hashPw(pwCheck(b.password)), created: Date.now() };
    saveAcc(); newSession(r, id); return send(r, 200, { user: pubUser(id, accounts.users[id]) }); }
  if (url === '/api/auth/login') { const login = String(b.login || '').trim().toLowerCase(), key = (q.socket.remoteAddress || '') + '|' + login, now = Date.now(), f = (fails.get(key) || []).filter(t => t > now - 15 * 60e3);
    if (f.length >= 5) return send(r, 429, { error: 'Trop d’essais : réessayez dans 15 minutes.' });
    const ent = Object.entries(accounts.users).find(([, u]) => u.login === login), pw = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
    const ok = ent ? checkPw(ent[1], pw) : (hashPw(pw), false);   // même durée que le compte existe ou non
    if (!ok) { f.push(now); fails.set(key, f); return send(r, 401, { error: 'Identifiant ou mot de passe incorrect.' }); }
    fails.delete(key); newSession(r, ent[0]); return send(r, 200, { user: pubUser(ent[0], ent[1]) }); }
  if (url === '/api/auth/logout') { const t = cookieTok(q); if (t) { delete sessions[sha(t)]; saveSess(); }
    r.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'sl_sess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }); return r.end('{"ok":true}'); }
  if (!me) return send(r, 401, { error: 'Connexion requise.' });
  if (url === '/api/auth/motdepasse') { const u = accounts.users[me.id]; if (!checkPw(u, b.old || '')) return send(r, 400, { error: 'Mot de passe actuel incorrect.' });
    Object.assign(u, hashPw(pwCheck(b.new))); delete u.mustChange; for (const [k, v] of Object.entries(sessions)) if (v.uid === me.id) delete sessions[k];
    saveAcc(); newSession(r, me.id); return send(r, 200, { ok: true }); }
  if (url === '/api/comptes') { if (me.role !== 'admin') return send(r, 403, { error: 'Réservé aux administrateurs.' });
    const U = accounts.users, admins = () => Object.values(U).filter(u => u.role === 'admin').length;
    if (b.op === 'create') { const login = loginCheck(b.login); if (Object.values(U).some(u => u.login === login)) throw new Error('Cet identifiant existe déjà.');
      U[crypto.randomUUID()] = { login, name: nameCheck(b.name), role: b.role === 'admin' ? 'admin' : 'tech', ...hashPw(pwCheck(b.password)), mustChange: true, created: Date.now() }; }
    else if (b.op === 'reset' || b.op === 'delete' || b.op === 'role') { const u = U[b.id]; if (!u) throw new Error('Compte inconnu.');
      if (b.op === 'reset') { Object.assign(u, hashPw(pwCheck(b.password)), { mustChange: true }); for (const [k, v] of Object.entries(sessions)) if (v.uid === b.id) delete sessions[k]; }
      if (b.op === 'role') { const role = b.role === 'admin' ? 'admin' : 'tech'; if (u.role === 'admin' && role !== 'admin' && admins() <= 1) throw new Error('Il faut garder au moins un administrateur.'); u.role = role; }
      if (b.op === 'delete') { if (b.id === me.id) throw new Error('Vous ne pouvez pas supprimer votre propre compte.'); if (u.role === 'admin' && admins() <= 1) throw new Error('Il faut garder au moins un administrateur.');
        delete U[b.id]; try { fs.unlinkSync(chatFile(b.id)); } catch (e) {} } }
    else if (b.op !== 'list') throw new Error('Opération inconnue.');
    if (b.op !== 'list') { saveAcc(); saveSess(); }
    return send(r, 200, { users: Object.entries(U).map(([id, u]) => ({ ...pubUser(id, u), mustChange: !!u.mustChange })) }); }
  return send(r, 404, { error: 'Inconnu.' }); }

// ---------- Assistant : une conversation appartient à un seul compte ----------
// Un fichier par compte (logs/conversations/<compte>.json, lisible par SysLens seul) : un compte ne peut ni lister ni ouvrir
// les conversations d'un autre, administrateur compris. Avant la création des comptes, tout est au compte « local ».
const chatFile = uid => path.join(CHAT_DIR, String(uid).replace(/[^a-z0-9-]/gi, '') + '.json');
const chatLoad = uid => { try { return JSON.parse(fs.readFileSync(chatFile(uid), 'utf8')); } catch (e) { return { convs: [] }; } };
const chatSave = (uid, d) => { fs.mkdirSync(CHAT_DIR, { recursive: true, mode: 0o700 }); writeSecret(chatFile(uid), d); };
const chatBusy = new Set();
function chatContext(cloud) {
  const mask = x => cloud ? String(x || '').replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<ip>').replace(/\b[0-9a-f]{2}([:-][0-9a-f]{2}){5}\b/gi, '<mac>') : String(x || '');
  const now = Date.now(), h = t => Math.round((now - t) / 60e3) + ' min', ref = k => REF_RAW.find(e => e.k === k) || {};
  const inc = [...incidents.values()].filter(I => now - I.last < 7 * 864e5).sort((a, b) => b.score - a.score || b.last - a.last).slice(0, 25).map(I => { const st = incEtat[`cli-test|${I.host || I.from}|${I.k}|${isPublic(I.src) ? I.src : ''}`];
    return `- [${I.score} ${I.level}] ${ref(I.k).sig || I.cat + ' : ' + mask(I.msg)} · équipement ${I.host || mask(I.from)} · ${I.count} log(s), dernier il y a ${h(I.last)} · ${I.status === 'résolu' || I.resolved ? 'revenu à la normale' : st ? (st.st === 'clos' ? 'clos par ' + (st.by || 'un technicien') : st.st) : 'ouvert'}${ref(I.k).act ? ' · à faire : ' + ref(I.k).act : ''}\n  exemple : ${mask(I.msg).slice(0, 160)}`; });
  const devs = [...devices.values()].slice(0, 40).map(d => `- ${d.host || mask(d.from)} (${famOfProduct(d.product || d.host)}${d.product ? ' ' + d.product : ''}) : dernier log il y a ${h(d.last)}${d.ping ? d.ping.ok ? `, répond au ping (${d.ping.ms} ms)` : d.ping.ip ? ', ne répond pas au ping' : ', pas d’adresse pour le ping' : ''}`);
  const c24 = [...counts.values()].filter(c => c.t >= now - 864e5), sum = k => c24.reduce((a, c) => a + (c[k] || 0), 0);
  return `État de SysLens au ${new Date(now).toLocaleString('fr-FR')} :
Logs reçus sur 24 h : ${sum('n')} (critiques ${sum('c')}, graves ${sum('g')}, moyens ${sum('m')}). Un incident regroupe les logs d'un même problème (type, équipement, source).
Équipements (${devices.size}) :
${devs.join('\n') || '- aucun'}
Incidents des 7 derniers jours, du plus grave au moins grave (${inc.length}) :
${inc.join('\n') || '- aucun'}`; }
const CHAT_SYS = `Tu es l'assistant de SysLens, un outil qui collecte et note par gravité les logs des équipements Zyxel (pare-feu, switchs, bornes Wi-Fi) d'un parc client.
Tu aides un technicien à comprendre et traiter les incidents. Réponds en français, de façon courte et concrète : ce qui se passe, la cause probable, quoi faire, dans l'ordre.
Appuie-toi sur l'état de SysLens ci-dessous ; cite l'équipement et l'incident concernés. Si l'information n'y est pas, dis-le au lieu d'inventer.
Ne demande jamais de mot de passe ni de clé, et n'en écris jamais. Pour une manipulation risquée (redémarrage, changement de configuration), préviens avant.`;
async function chatApi(q, r, me, url) {
  const uid = me ? me.id : hasAccounts() ? null : 'local'; if (!uid) return send(r, 401, { error: 'Connexion requise.' });
  const d = chatLoad(uid), id = url.split('/')[3];
  if (q.method === 'GET') { if (!id) return send(r, 200, { convs: d.convs.map(c => ({ id: c.id, title: c.title, updated: c.updated, n: c.msgs.length })).sort((a, b) => b.updated - a.updated) });
    const c = d.convs.find(x => x.id === id); return c ? send(r, 200, c) : send(r, 404, { error: 'Conversation introuvable.' }); }
  if (q.method !== 'POST' || !sameOrigin(q)) return send(r, 403, { error: 'Refusé.' });
  const b = await readBody(q, 64 << 10);
  if (b.op === 'delete' || b.op === 'rename') { const c = d.convs.find(x => x.id === b.id); if (!c) return send(r, 404, { error: 'Conversation introuvable.' });
    if (b.op === 'delete') d.convs = d.convs.filter(x => x !== c); else c.title = String(b.title || '').trim().slice(0, 80) || c.title; chatSave(uid, d); return send(r, 200, { ok: true }); }
  if (b.op !== 'send') return send(r, 400, { error: 'Opération inconnue.' });
  const text = String(b.text || '').trim().slice(0, 4000); if (!text) return send(r, 400, { error: 'Message vide.' });
  if (chatBusy.has(uid)) return send(r, 429, { error: 'Une réponse est déjà en cours.' });
  let c = b.id ? d.convs.find(x => x.id === b.id) : null; if (b.id && !c) return send(r, 404, { error: 'Conversation introuvable.' });
  if (!c) { c = { id: crypto.randomBytes(12).toString('hex'), title: text.replace(/\s+/g, ' ').slice(0, 60), created: Date.now(), updated: Date.now(), msgs: [] }; d.convs.push(c);
    if (d.convs.length > 200) d.convs.sort((a, x) => x.updated - a.updated).splice(200); }
  const ai = b.ai || {}, cloud = ai.mode !== 'local' && ai.prov !== 'ollama';
  c.msgs.push({ role: 'user', content: text, t: Date.now() }); chatBusy.add(uid);
  try { const hist = c.msgs.slice(-20).map(m => ({ role: m.role, content: m.content }));
    const out = await aiAsk(ai, [{ role: 'system', content: CHAT_SYS + '\n\n' + chatContext(cloud) }, ...hist], null, 1500, false);
    c.msgs.push({ role: 'assistant', content: String(out || '').trim() || '(réponse vide)', t: Date.now(), model: (ai.model || ai.prov || '') + (aiStats.last && (ai.mode === 'local' || ai.prov === 'ollama') ? ` · ${aiStats.last.tps} tok/s` : '') }); }
  catch (e) { c.msgs.push({ role: 'assistant', content: 'Je n’ai pas pu répondre : ' + e.message, t: Date.now(), error: true }); }
  finally { chatBusy.delete(uid); }
  c.updated = Date.now(); chatSave(uid, d); return send(r, 200, c); }

const webSrv = http.createServer((q, r) => {
  const url = q.url.split('?')[0], me = who(q);
  if (url.startsWith('/api/auth/') || url === '/api/comptes') return void authApi(q, r, me, url).catch(e => send(r, 400, { error: e.message }));
  if (url === '/api/chat' || url.startsWith('/api/chat/')) return void chatApi(q, r, me, url).catch(e => send(r, 400, { error: e.message }));
  // Avec des comptes, tout le reste demande une session. Seule exception : la mise à jour lancée en ligne de commande sur ce poste
  // (pas de navigateur : ni Origin ni cookie) ; elle n'installe de toute façon qu'une version signée du dépôt.
  if (hasAccounts() && !me && !url.startsWith('/console') && !url.startsWith('/ext/')) {
    const cli = url === '/api/update' && q.method === 'POST' && isLoop(q) && !q.headers.origin && !q.headers.cookie;
    if (!cli) { if (url === '/') { r.writeHead(302, { location: '/console' }); return r.end(); } return send(r, 401, { error: 'Connexion requise.' }); } }
  q.me = me;
  if (q.url === '/api/version') { let news = []; try { news = JSON.parse(fs.readFileSync(path.join(__dirname, 'nouveautes.json'), 'utf8')).slice(0, 5); } catch (e) {} r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify({ ...upd, news })); }
  else if (q.url === '/api/update' && q.method === 'POST') { const json = o => { r.writeHead(sameOrigin(q) ? 200 : 403, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json({ error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 256) q.destroy(); });
    q.on('end', async () => { let install = false; try { install = !!JSON.parse(body).install; } catch (e) {} json(await checkUpdate(install)); }); }
  else if (q.url.startsWith('/api/events')) { const since = +(new URL(q.url, 'http://x').searchParams.get('since') || 0); r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); const evs = []; for (let i = hist.length - 1; i >= 0 && hist[i].id > since && evs.length < 5000; i--) evs.push(hist[i]); evs.reverse();
    r.end(JSON.stringify({ version: VERSION, stats: { rate: lastRate, total, workers: WORKERS, devices: devices.size, incidents: incidents.size }, counts: [...counts.values()].filter(c => c.t >= Date.now() - 26 * 3600e3), devices: [...devices.values()], events: evs })); }
  else if (q.url.startsWith('/api/incidents') && !q.url.startsWith('/api/incidents-etat')) { const lv = new URL(q.url, 'http://x').searchParams.get('level'); const out = []; for (const I of incidents.values()) if (!lv || I.level === lv) out.push(I);
    out.sort((a, b) => b.last - a.last); r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify({ total: out.length, incidents: out.slice(0, 2000) })); }
  else if (q.url.startsWith('/console')) { fs.readFile(path.join(__dirname, 'console.html'), (err, b) => { r.writeHead(err ? 404 : 200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); r.end(err ? 'console.html introuvable' : b); }); }
  else if (q.url === '/api/ai' && q.method === 'POST') {
    const json = (code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json(403, { error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 8192) q.destroy(); });
    q.on('end', async () => { try { json(200, await aiApi(JSON.parse(body))); } catch (e) { json(400, { error: e.message }); } }); }
  else if (q.url === '/api/incidents-etat' && q.method === 'GET') { r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify({ etat: incEtat })); }
  else if (q.url === '/api/incidents-etat' && q.method === 'POST') {
    const json = (code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json(403, { error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 4096) q.destroy(); });
    q.on('end', () => { try { json(200, incApi(JSON.parse(body), q.me)); } catch (e) { json(400, { error: e.message }); } }); }
  else if (q.url === '/api/referentiel') { r.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(refPayload())); }
  else if (q.url === '/api/ref' && q.method === 'POST') {
    const json = (code, o) => { r.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (!sameOrigin(q)) return json(403, { error: 'Refusé.' }); let body = ''; q.on('data', d => { body += d; if (body.length > 16384) q.destroy(); });
    q.on('end', async () => { try { json(200, await refApi(JSON.parse(body), q.me)); } catch (e) { json(400, { error: e.message }); } }); }
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
  setTimeout(go, 4000); evOut.end(); rawOut.end(); countsDirty = true; saveCounts(true); typesDirty = true; try { fs.writeFileSync(TYPES_FILE, JSON.stringify([...types.values()].sort((a, b) => b.count - a.count), null, 1)); } catch (e) {}
  if (rx) { try { rx.udp.close(); } catch (e) {} rx.tcp.close(); } for (const w of Object.values(cluster.workers || {})) w.kill();
  webSrv.close(() => setTimeout(go, 300)); if (webSrv.closeAllConnections) webSrv.closeAllConnections(); }

if (SELFTEST) { console.log('selftest ok ' + VERSION + ' · référentiel ' + REF.length + ' entrées'); process.exit(0); }
for (const sg of ['SIGINT', 'SIGTERM']) process.on(sg, () => { countsDirty = true; saveCounts(true); try { if (typesDirty) fs.writeFileSync(TYPES_FILE, JSON.stringify([...types.values()].sort((a, b) => b.count - a.count), null, 1)); } catch (e) {} process.exit(0); });
if (WORKERS) startWorkers(); else rx = startReceivers(stage1);
setTimeout(maintain, 5000).unref(); setInterval(maintain, 3600e3).unref();
setInterval(() => { if (lastRate || incidents.size) console.log(`\x1b[2mDébit ${lastRate} logs/s · ${devices.size} équipements · ${incidents.size} incidents · ${WORKERS || 1} processus de réception\x1b[0m`); }, 300e3).unref();
webSrv.listen(WEB, '127.0.0.1', () => {
  const ips = Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal).map(i => i.address);
  console.log(`SysLens ${VERSION} — écoute syslog UDP et TCP ${BIND}:${PORT} (${WORKERS ? WORKERS + ' processus de réception' : '1 processus'})${ALLOW.length ? ', logs acceptés seulement depuis ' + process.env.ALLOW : ''}\nIP à mettre dans le USG (serveur distant) : ${ips.join(' ou ') || 'aucune IP détectée'}\nPage de suivi : http://localhost:${WEB}\nConsole SysLens : http://localhost:${WEB}/console\nFichiers : ${DIR}\nMise à jour auto : ${upd.auto ? 'activée (' + REPO + ', releases)' : 'désactivée'}\nCtrl+C pour arrêter.\n`);
});
if (upd.auto) { setTimeout(() => checkUpdate(true), 60e3); setInterval(() => checkUpdate(true), 3600e3); }
