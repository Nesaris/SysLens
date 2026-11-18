'use strict';
// Essais de bout en bout : un vrai serveur SysLens, du vrai syslog en UDP, la vraie console HTTP.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process'), dgram = require('node:dgram'), http = require('node:http');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');

const RACINE = path.join(__dirname, '..');
const FICHIERS = ['syslens.js', 'console.html', 'referentiel.json', 'package.json', 'nouveautes.json'];
const enfants = [];
after(() => enfants.forEach(p => { try { p.kill(); } catch (e) {} }));

let port = 21000 + Math.floor(Math.random() * 20000);
const ports = () => ({ syslog: port++, web: port++ });
const attendre = ms => new Promise(r => setTimeout(r, ms));
const cef = (nom, sev, champs) => `<${8 * 17 + sev}>Nov 16 08:53:10 usgflex50w CEF:0|ZyXEL|USG20W-VPN|5.42(ABAR.1)|0|${nom}|${sev}|devID=a0b1c2d3e4f5 dvchost=usgflex50w ${champs}`;

function installer(dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'syslens-essai-'))) {
  for (const f of FICHIERS) fs.copyFileSync(path.join(RACINE, f), path.join(dossier, f));
  return dossier;
}
async function demarrer(env = {}, dossier = installer()) {
  const p = ports(), sortie = [];
  const proc = cp.spawn(process.execPath, [path.join(dossier, 'syslens.js')], { env: { ...process.env, PORT: String(p.syslog), WEB: String(p.web), BIND: '127.0.0.1', SYSLENS_AUTOUPDATE: '0', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  enfants.push(proc); proc.stdout.on('data', d => sortie.push(String(d))); proc.stderr.on('data', d => sortie.push(String(d)));
  for (let i = 0; i < 100 && !sortie.join('').includes('Ctrl+C'); i++) await attendre(50);
  assert.match(sortie.join(''), /Ctrl\+C/, 'le serveur doit démarrer : ' + sortie.join(''));
  return { ...p, proc, dossier, sortie };
}
function envoyer(portSyslog, lignes) {
  const s = dgram.createSocket('udp4');
  return Promise.all(lignes.map(l => new Promise(r => s.send(l, portSyslog, '127.0.0.1', r)))).then(() => s.close());
}
function requete(portWeb, chemin, { methode = 'GET', corps, entetes = {} } = {}) {
  return new Promise((ok, ko) => {
    const q = http.request({ host: '127.0.0.1', port: portWeb, path: chemin, method: methode, headers: entetes }, r => {
      let b = ''; r.on('data', d => b += d); r.on('end', () => { let json = null; try { json = JSON.parse(b); } catch (e) {} ok({ statut: r.statusCode, json, texte: b, entetes: r.headers }); });
    });
    q.on('error', ko); if (corps) q.write(corps); q.end();
  });
}
const evenements = async w => (await requete(w, '/api/events?since=0')).json.events;

test('--selftest charge le serveur sans ouvrir de port', () => {
  const r = cp.spawnSync(process.execPath, [path.join(RACINE, 'syslens.js'), '--selftest'], { encoding: 'utf8', env: { ...process.env, SYSLENS_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'syslens-st-')) } });
  assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /selftest ok v\d+\.\d+\.\d+/);
});

test('la version de package.json a son entrée en tête de nouveautes.json', () => {
  const p = require('../package.json'), n = require('../nouveautes.json');
  assert.equal(n[0].version, p.version); assert.ok(n[0].points.length > 0);
});

test('aucune dépendance npm', () => {
  const p = require('../package.json');
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) assert.ok(!p[k] || !Object.keys(p[k]).length, k);
});

test('reçoit du CEF Zyxel et note chaque log', async () => {
  const s = await demarrer();
  await envoyer(s.syslog, [
    cef('INTERFACE STATISTICS', 5, 'msg=name:Port4,status:Down,TxPkts:0,RxPkts:0 cat=INTERFACE STATISTICS ZYlevel=notice'),
    cef('System', 1, 'msg=Port 3 is down! cat=System ZYlevel=alert'),
    cef('Access Control', 5, 'src=192.0.2.10 dst=255.255.255.255 msg=Match default rule, DROP act=Drop cat=Security Policy Control')
  ]);
  await attendre(300);
  const ev = await evenements(s.web);
  assert.equal(ev.length, 3);
  const stats = ev.find(e => e.cat === 'INTERFACE STATISTICS'), coupure = ev.find(e => e.msg === 'Port 3 is down!');
  assert.equal(stats.k, 'if-stats'); assert.equal(stats.level, 'benin', 'un relevé périodique « Down » n’est pas une panne');
  assert.equal(coupure.k, 'link-down'); assert.equal(coupure.level, 'grave'); assert.match(coupure.why, /pare-feu de tête/);
  assert.equal(stats.product, 'USG20W-VPN'); assert.ok(coupure.raw.startsWith('<137>'));
  let dev = []; for (let i = 0; i < 30 && !dev.length; i++) { await attendre(100); dev = (await requete(s.web, '/api/events?since=0')).json.devices; }
  assert.equal(dev.length, 1); assert.equal(dev[0].count, 3);
});

test('ALLOW écarte les sources non autorisées', async () => {
  const s = await demarrer({ ALLOW: '10.0.0.0/8' });
  await envoyer(s.syslog, [cef('System', 1, 'msg=Port 3 is down! cat=System')]);
  await attendre(300);
  assert.equal((await evenements(s.web)).length, 0);
  assert.match(s.sortie.join(''), /Ignoré : log venant de 127\.0\.0\.1/);
});

test('la console est servie et les appels sensibles refusent les autres sites', async () => {
  const s = await demarrer();
  const page = await requete(s.web, '/console');
  assert.equal(page.statut, 200); assert.match(page.texte, /<title>SysLens/);
  const json = { 'content-type': 'application/json' };
  assert.equal((await requete(s.web, '/api/update', { methode: 'POST', corps: '{}', entetes: { ...json, origin: 'https://exemple.com' } })).statut, 403);
  assert.equal((await requete(s.web, '/api/update', { methode: 'POST', corps: '{}', entetes: { 'content-type': 'text/plain' } })).statut, 403);
  assert.equal((await requete(s.web, '/api/tg', { methode: 'POST', corps: '{}', entetes: { ...json, origin: 'https://exemple.com' } })).statut, 403);
  const v = (await requete(s.web, '/api/version')).json;
  assert.equal(v.version, 'v' + require('../package.json').version); assert.ok(Array.isArray(v.news));
});

// Faux GitHub : une release v99.0.0 dont les fichiers sont ceux du dépôt, version changée.
async function fauxGitHub({ alterer = false } = {}) {
  const tag = 'v99.0.0', fichiers = {};
  for (const f of FICHIERS) fichiers[f] = fs.readFileSync(path.join(RACINE, f));
  const pkg = JSON.parse(fichiers['package.json']); pkg.version = '99.0.0'; fichiers['package.json'] = Buffer.from(JSON.stringify(pkg, null, 2));
  const sommes = FICHIERS.map(f => crypto.createHash('sha256').update(fichiers[f]).digest('hex') + '  ' + f).join('\n') + '\n';
  if (alterer) fichiers['syslens.js'] = Buffer.concat([fichiers['syslens.js'], Buffer.from('\n// modifié après publication\n')]);
  const srv = http.createServer((q, r) => {
    if (q.url === '/repos/Nesaris/SysLens/releases/latest') { r.writeHead(200, { 'content-type': 'application/json' }); return r.end(JSON.stringify({ tag_name: tag, html_url: 'https://exemple.invalid' })); }
    const m = /^\/Nesaris\/SysLens\/v99\.0\.0\/([\w.-]+)$/.exec(q.url);
    if (m && m[1] === 'SHA256SUMS') { r.writeHead(200); return r.end(sommes); }
    if (m && fichiers[m[1]]) { r.writeHead(200); return r.end(fichiers[m[1]]); }
    r.writeHead(404); r.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r)); after(() => srv.close());
  return 'http://127.0.0.1:' + srv.address().port;
}
const maj = (w, install) => requete(w, '/api/update', { methode: 'POST', corps: JSON.stringify({ install }), entetes: { 'content-type': 'application/json' } });

test('mise à jour : vérifie, installe, garde l’ancienne version et redémarre', async () => {
  const gh = await fauxGitHub(), s = await demarrer({ SYSLENS_GH_API: gh, SYSLENS_GH_RAW: gh });
  const dispo = (await maj(s.web, false)).json;
  assert.equal(dispo.state, 'available'); assert.equal(dispo.latest, 'v99.0.0');
  await maj(s.web, true).catch(() => {});
  let v = null;
  for (let i = 0; i < 80 && (!v || v.version !== 'v99.0.0'); i++) { await attendre(100); v = (await requete(s.web, '/api/version').catch(() => ({}))).json; }
  assert.equal(v && v.version, 'v99.0.0', 'le nouveau processus doit répondre');
  assert.ok(fs.existsSync(path.join(s.dossier, '.previous', 'syslens.js')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dossier, '.previous', 'package.json'))).version, require('../package.json').version);
  cp.spawnSync(process.platform === 'win32' ? 'taskkill' : 'pkill', ['-f', path.join(s.dossier, 'syslens.js')]);
});

test('mise à jour : un fichier qui ne correspond pas à SHA256SUMS est refusé', async () => {
  const gh = await fauxGitHub({ alterer: true }), s = await demarrer({ SYSLENS_GH_API: gh, SYSLENS_GH_RAW: gh });
  const r = (await maj(s.web, true)).json;
  assert.equal(r.state, 'error'); assert.match(r.msg, /Empreinte incorrecte pour syslens\.js/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dossier, 'package.json'))).version, require('../package.json').version, 'rien n’a été remplacé');
  assert.ok(!fs.existsSync(path.join(s.dossier, '.previous')));
});

test('IA : la liste des modèles d’Ollama passe par le serveur, et une clé courte est refusée sans appel', async () => {
  const ollama = http.createServer((q, r) => { r.writeHead(q.url === '/api/tags' ? 200 : 404, { 'content-type': 'application/json' }); r.end(JSON.stringify({ models: [{ name: 'qwen3:8b' }, { name: 'hermes3:8b' }] })); });
  await new Promise(r => ollama.listen(0, '127.0.0.1', r)); after(() => ollama.close());
  const s = await demarrer(), json = { 'content-type': 'application/json' };
  const ok = await requete(s.web, '/api/ai', { methode: 'POST', corps: JSON.stringify({ op: 'models', provider: 'ollama', url: 'http://127.0.0.1:' + ollama.address().port }), entetes: json });
  assert.deepEqual(ok.json.models, ['hermes3:8b', 'qwen3:8b']);
  const ko = await requete(s.web, '/api/ai', { methode: 'POST', corps: JSON.stringify({ op: 'models', provider: 'claude', key: 'court' }), entetes: json });
  assert.equal(ko.statut, 400); assert.match(ko.json.error, /Clé invalide/);
  assert.equal((await requete(s.web, '/api/ai', { methode: 'POST', corps: '{}', entetes: { ...json, origin: 'https://exemple.com' } })).statut, 403);
});

test('logo d’extension : une page HTML servie à l’adresse de l’icône est écartée au profit d’une vraie image', async () => {
  const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a6a20000000049454e44ae426082', 'hex');
  const site = http.createServer((q, r) => {
    if (q.url === '/') { r.writeHead(200, { 'content-type': 'text/html' }); return r.end('<link rel="icon" type="image/svg+xml" href="/piege.svg"><link rel="apple-touch-icon" href="/vrai.png" sizes="180x180">'); }
    if (q.url === '/piege.svg') { r.writeHead(200, { 'content-type': 'image/svg+xml' }); return r.end('<!DOCTYPE html><html><body><svg></svg>Vérification anti-robot</body></html>'); }
    if (q.url === '/vrai.png') { r.writeHead(200, { 'content-type': 'image/png' }); return r.end(png); }
    r.writeHead(404); r.end(); });
  await new Promise(r => site.listen(0, '127.0.0.1', r)); after(() => site.close());
  const s = await demarrer({ EXT_SITES: JSON.stringify({ essai: 'http://127.0.0.1:' + site.address().port }) });
  const r = await requete(s.web, '/ext/essai/logo');
  assert.equal(r.statut, 302);
  assert.ok(fs.existsSync(path.join(s.dossier, 'extensions', 'essai', 'logo.png')));
  assert.ok(!fs.existsSync(path.join(s.dossier, 'extensions', 'essai', 'logo.svg')));
});

test('logo d’extension : remplacé quand sa source change dans une nouvelle version', async () => {
  const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a6a20000000049454e44ae426082', 'hex');
  const site = http.createServer((q, r) => {
    if (q.url === '/a.png') { r.writeHead(200, { 'content-type': 'image/png' }); return r.end(png); }
    if (q.url === '/b.svg') { r.writeHead(200, { 'content-type': 'image/svg+xml' }); return r.end('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>'); }
    r.writeHead(404); r.end(); });
  await new Promise(r => site.listen(0, '127.0.0.1', r)); after(() => site.close());
  const base = 'http://127.0.0.1:' + site.address().port, ext = d => path.join(d, 'extensions', 'essai');
  const s1 = await demarrer({ EXT_SITES: JSON.stringify({ essai: 'img:' + base + '/a.png' }) });
  assert.equal((await requete(s1.web, '/ext/essai/logo')).statut, 302); assert.ok(fs.existsSync(path.join(ext(s1.dossier), 'logo.png')));
  s1.proc.kill(); await attendre(200);
  const s2 = await demarrer({ EXT_SITES: JSON.stringify({ essai: 'img:' + base + '/b.svg' }) }, s1.dossier);
  const r = await requete(s2.web, '/ext/essai/logo');
  assert.equal(r.statut, 302); assert.match(r.entetes.location, /logo\.svg$/);
  assert.ok(!fs.existsSync(path.join(ext(s1.dossier), 'logo.png')));
});

test('abonnement : connexion suivie par le serveur (Codex par la page, Claude Code par code collé)', { skip: process.platform === 'win32' }, async () => {
  const dossier = installer(), bin = path.join(dossier, 'outils', 'node_modules', '.bin'); fs.mkdirSync(bin, { recursive: true });
  const faux = (nom, corps) => { fs.writeFileSync(path.join(bin, nom), '#!/usr/bin/env node\nconst fs = require("fs"), ok = __dirname + "/' + nom + '-ok", a = process.argv.slice(2).join(" ");\nif (a === "--version") { console.log("' + nom + ' 9.9"); process.exit(0); }\n' + corps); fs.chmodSync(path.join(bin, nom), 0o755); };
  faux('codex', 'if (a === "login status") process.exit(fs.existsSync(ok) ? 0 : 1);\nif (a === "login") { console.log("Ouvrez https://auth.openai.com/oauth/authorize?essai=1"); setTimeout(() => { fs.writeFileSync(ok, ""); process.exit(0); }, 1500); }');
  faux('claude', 'if (a === "auth status --json") { console.log(JSON.stringify({ loggedIn: fs.existsSync(ok) })); process.exit(0); }\nif (a === "auth login --claudeai") { console.log("visit: https://claude.com/cai/oauth/authorize?essai=1\\nPaste code here if prompted >"); process.stdin.on("data", d => { if (String(d).trim() === "CODE-essai-123") { fs.writeFileSync(ok, ""); process.exit(0); } else process.exit(1); }); }');
  const s = await demarrer({}, dossier), json = { 'content-type': 'application/json' };
  const ia = o => requete(s.web, '/api/ai', { methode: 'POST', corps: JSON.stringify(o), entetes: json }).then(r => r.json);
  let c = await ia({ op: 'cli', tool: 'codex' }); assert.equal(c.installed, true); assert.equal(c.logged, false);
  c = await ia({ op: 'login', tool: 'codex' }); assert.equal(c.job.phase, 'login'); assert.match(c.job.url, /^https:\/\/auth\.openai\.com\//);
  for (let i = 0; i < 40 && !(c.logged); i++) { await attendre(150); c = await ia({ op: 'cli', tool: 'codex' }); } assert.equal(c.logged, true);
  c = await ia({ op: 'login', tool: 'claudecode' }); assert.equal(c.job.code, true); assert.match(c.job.url, /^https:\/\/claude\.com\//);
  assert.match((await ia({ op: 'code', tool: 'claudecode', code: 'pas de code' })).error, /Code invalide/);
  await ia({ op: 'code', tool: 'claudecode', code: 'CODE-essai-123' });
  for (let i = 0; i < 40 && !(c.logged); i++) { await attendre(150); c = await ia({ op: 'cli', tool: 'claudecode' }); } assert.equal(c.logged, true);
  assert.match((await ia({ op: 'install', tool: 'inconnu' })).error, /Outil inconnu/);
});

test('grande échelle : plusieurs processus de réception, équipements derrière la même IP séparés, bénins non réécrits', async () => {
  const s = await demarrer({ WORKERS: '2' }); await attendre(800);
  const lignes = [];
  for (let i = 0; i < 300; i++) lignes.push(cef('Access Control', 6, `src=203.0.113.${i % 200} dst=192.0.2.1 msg=Match default rule, DROP act=Drop cat=Security Policy Control`));
  lignes.push('<187>Nov 16 15:00:00 XMG1915-10E: Port 3 link down');
  await envoyer(s.syslog, lignes);
  let st; await attendre(5500); for (let i = 0; i < 40; i++) { await attendre(150); st = (await requete(s.web, '/api/events?since=0')).json; if (st.devices.length === 2 && st.devices.reduce((a, d) => a + d.count, 0) === 301) break; }
  assert.equal(st.stats.workers, 2);
  assert.equal(st.devices.length, 2, 'le routeur et le switch derrière la même IP sont deux équipements');
  assert.equal(st.devices.reduce((a, d) => a + d.count, 0), 301);
  const sw = st.devices.find(d => d.host === 'XMG1915-10E'); assert.equal(sw.product, 'XMG1915-10E');
  const inc = (await requete(s.web, '/api/incidents')).json; assert.equal(inc.total, 1); assert.equal(inc.incidents[0].k, 'link-down'); assert.equal(inc.incidents[0].level, 'grave');
  const fichiers = fs.readdirSync(path.join(s.dossier, 'logs'));
  const zl = require('zlib'), bruts = fichiers.filter(f => /^raw-.*\.w\d+\.log\.gz$/.test(f)).reduce((a, f) => a + zl.gunzipSync(fs.readFileSync(path.join(s.dossier, 'logs', f)), { finishFlush: zl.constants.Z_SYNC_FLUSH }).toString().split('\n').filter(Boolean).length, 0);
  assert.equal(bruts, 301, 'tout le brut est archivé');
  const utiles = fs.readFileSync(path.join(s.dossier, 'logs', fichiers.find(f => f.startsWith('events-'))), 'utf8').split('\n').filter(Boolean);
  assert.equal(utiles.length, 1, 'seuls les événements utiles sont réécrits');
});

test('archives : jours passés compressés, au-delà de la rétention supprimés', async () => {
  const dossier = installer(), logs = path.join(dossier, 'logs'); fs.mkdirSync(logs);
  const j = n => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10), vieux = Date.now() / 1000 - 86400;
  fs.writeFileSync(path.join(logs, `raw-${j(3)}.log`), 'ligne\n'.repeat(100)); fs.writeFileSync(path.join(logs, `raw-${j(120)}.log`), 'x\n');
  // Un jour qui a déjà son archive .gz (version précédente) : la compression ajoute, n'écrase pas.
  const zl = require('zlib'); fs.writeFileSync(path.join(logs, `raw-${j(2)}.log.gz`), zl.gzipSync('avant\n')); fs.writeFileSync(path.join(logs, `raw-${j(2)}.log`), 'apres\n');
  for (const f of fs.readdirSync(logs)) fs.utimesSync(path.join(logs, f), vieux, vieux);
  await demarrer({ RETENTION_DAYS: '90' }, dossier);
  for (let i = 0; i < 60 && !fs.existsSync(path.join(logs, `raw-${j(3)}.log.gz`)); i++) await attendre(200);
  const zlib = require('zlib');
  assert.equal(zlib.gunzipSync(fs.readFileSync(path.join(logs, `raw-${j(3)}.log.gz`))).toString(), 'ligne\n'.repeat(100));
  assert.ok(!fs.existsSync(path.join(logs, `raw-${j(3)}.log`)));
  assert.ok(!fs.existsSync(path.join(logs, `raw-${j(120)}.log`)), 'au-delà de 90 jours : supprimé');
  for (let i = 0; i < 30 && fs.existsSync(path.join(logs, `raw-${j(2)}.log`)); i++) await attendre(200);
  assert.equal(zlib.gunzipSync(fs.readFileSync(path.join(logs, `raw-${j(2)}.log.gz`))).toString(), 'avant\napres\n', 'archive existante gardée');
});

test('switch Zyxel en syslog à horodatage ISO : nom, modèle, source et utilisateur reconnus', async () => {
  const s = await demarrer();
  await envoyer(s.syslog, ['<133> 2026-11-16T16:07:44Z XMG1915 authentication: HTTP(s) authentication failure [username: essai, IP address = 192.168.1.33]']);
  let ev = []; for (let i = 0; i < 20 && !ev.length; i++) { await attendre(100); ev = await evenements(s.web); }
  assert.equal(ev[0].host, 'XMG1915'); assert.equal(ev[0].product, 'XMG1915'); assert.equal(ev[0].k, 'admin-ko');
  assert.equal(ev[0].src, '192.168.1.33'); assert.equal(ev[0].user, 'essai');
});

test('classement : retour à la normale, plafond des types inconnus, DHCP de routine', async () => {
  const s = await demarrer();
  await envoyer(s.syslog, [
    cef('System', 1, 'msg=Port 3 is down! cat=System ZYlevel=alert'),
    cef('Policy Route', 1, 'msg=Interface lan1 dead, related policy route rules will be disabled. cat=Policy Route ZYlevel=alert'),
    cef('DHCP', 6, 'msg=DHCP server assigned 192.168.1.34 to XMG1915(70:49:A2:21:D0:6D) act=DHCP ACK cat=DHCP ZYlevel=info'),
    cef('Inconnu', 1, 'msg=Quelque chose de jamais vu cat=Inconnu ZYlevel=alert')]);
  await attendre(300);
  await envoyer(s.syslog, [cef('System', 1, 'msg=Port 3 is up! cat=System ZYlevel=alert')]);
  let inc; for (let i = 0; i < 20; i++) { await attendre(100); inc = (await requete(s.web, '/api/incidents')).json.incidents; if (inc.some(x => x.status === 'résolu')) break; }
  const lien = inc.find(x => x.k === 'link-down'); assert.equal(lien.count, 2, '« lan1 dead » rejoint l’incident du port tombé'); assert.equal(lien.status, 'résolu');
  const inconnu = inc.find(x => x.k === 'inconnu'); assert.equal(inconnu.score, 75); assert.equal(inconnu.level, 'grave');
  assert.ok(!inc.some(x => x.level === 'critique'), 'aucune fausse alerte critique');
  const ev = await evenements(s.web); assert.equal(ev.find(e => /Port 3 is up/.test(e.msg)).level, 'benin');
  assert.ok(!inc.some(x => x.k === 'dhcp'));
});

test('référentiel : types cumulés après redémarrage, classement par l’IA, validation, la proposition ne baisse jamais la note', async () => {
  const json = { 'content-type': 'application/json' }, dossier = installer();
  const ligne = cef('Truc Bizarre', 1, 'msg=Le module 7 a fait quelque chose cat=Truc Bizarre ZYlevel=alert');
  let s = await demarrer({}, dossier);
  await envoyer(s.syslog, [ligne, cef('User', 5, 'msg=Administrator admin from https has logged in Device cat=User suser=admin spriv=Administrator')]);
  let ref; for (let i = 0; i < 30; i++) { await attendre(100); ref = (await requete(s.web, '/api/referentiel')).json; if (ref.queue === 1) break; }
  assert.ok(ref.entries.length > 100, 'référentiel livré'); assert.equal(ref.queue, 1, 'un seul type à qualifier');
  const t = ref.types.find(x => x.cov === 'qualifier'); assert.equal(t.msg, 'Le module # a fait quelque chose');
  assert.ok(ref.types.some(x => x.k === 'admin-ok' && x.cov === 'precis'));
  // Redémarrage : types.json est relu, la file aussi.
  await attendre(16000); s.proc.kill(); await attendre(300);
  s = await demarrer({}, dossier);
  ref = (await requete(s.web, '/api/referentiel')).json; assert.equal(ref.queue, 1, 'types gardés après redémarrage');
  // Faux Ollama : propose 20 (bénin) pour ce type.
  let recu = '';
  const ollama = http.createServer((q, r) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { recu = b; r.writeHead(200, json);
    r.end(JSON.stringify({ message: { content: '{"types":[{"id":1,"base":20,"sig":"Module bizarre","mean":"Essai.","act":"Rien.","confiance":0.4}]}' } })); }); });
  await new Promise(r => ollama.listen(0, '127.0.0.1', r)); after(() => ollama.close());
  const c = await requete(s.web, '/api/ref', { methode: 'POST', entetes: json, corps: JSON.stringify({ op: 'classify', ai: { prov: 'ollama', mode: 'local', url: 'http://127.0.0.1:' + ollama.address().port, model: 'qwen3:8b' } }) });
  assert.equal(c.statut, 200, c.texte); assert.equal(c.json.proposed, 1); assert.equal(c.json.left, 0);
  const lot = JSON.parse(recu).messages[0].content.split('Types à noter :')[1]; assert.match(lot, /Le module # a fait quelque chose/); assert.ok(!/192\.168|admin/.test(lot), 'rien d’identifiant ne part vers l’IA');
  // Proposition 20 < gravité annoncée (alert, plafonnée à 75) : la note reste 75 tant que ce n’est pas validé.
  await envoyer(s.syslog, [ligne]); let ev; for (let i = 0; i < 20; i++) { await attendre(100); ev = (await evenements(s.web)).filter(e => /module 7/.test(e.msg)); if (ev.length) break; }
  assert.equal(ev.pop().score, 75);
  const v = await requete(s.web, '/api/ref', { methode: 'POST', entetes: json, corps: JSON.stringify({ op: 'valide', key: t.key }) }); assert.equal(v.statut, 200, v.texte);
  await envoyer(s.syslog, [ligne]); for (let i = 0; i < 20; i++) { await attendre(100); ev = (await evenements(s.web)).filter(e => /module 7/.test(e.msg)); if (ev.length > 1) break; }
  const e = ev.pop(); assert.equal(e.score, 20); assert.equal(e.cov, 'appris'); assert.match(e.k, /^appris:/);
  assert.ok(fs.existsSync(path.join(dossier, 'logs', 'ref-appris.json')));
  const refus = await requete(s.web, '/api/ref', { methode: 'POST', entetes: { ...json, origin: 'https://exemple.com' }, corps: JSON.stringify({ op: 'oublier', key: t.key }) }); assert.equal(refus.statut, 403);
});

test('compteurs : tous les logs comptés par tranche de 5 min, gardés au redémarrage, et les 24 h d’événements rechargées', async () => {
  const dossier = installer(); let s = await demarrer({ BENIN: '0' }, dossier);
  const benins = Array.from({ length: 40 }, (_, i) => cef('INTERFACE STATISTICS', 5, `msg=name:Port${i % 5},status:Down,TxPkts:0 cat=INTERFACE STATISTICS ZYlevel=notice`));
  await envoyer(s.syslog, [...benins, cef('System', 1, 'msg=Port 3 is down! cat=System ZYlevel=alert')]);
  let j; for (let i = 0; i < 30; i++) { await attendre(100); j = (await requete(s.web, '/api/events?since=0')).json; if (j.counts && j.counts.reduce((a, c) => a + c.n, 0) === 41) break; }
  const somme = k => j.counts.reduce((a, c) => a + c[k], 0); assert.equal(somme('n'), 41); assert.equal(somme('g'), 1); assert.equal(somme('fw'), 41);
  s.proc.kill('SIGTERM'); await attendre(400); assert.ok(fs.existsSync(path.join(dossier, 'logs', 'compteurs.json')));
  // Les événements d'hier (dans les 24 h) sont rechargés depuis l'archive compressée.
  const hier = new Date(Date.now() - 864e5).toISOString().slice(0, 10), zlib = require('zlib');
  fs.writeFileSync(path.join(dossier, 'logs', `events-${hier}.jsonl.gz`), zlib.gzipSync(JSON.stringify({ t: Date.now() - 3600e3, from: '127.0.0.1', raw: cef('System', 1, 'msg=Port 4 is down! cat=System ZYlevel=alert') }) + '\n'));
  s = await demarrer({}, dossier); j = (await requete(s.web, '/api/events?since=0')).json;
  assert.equal(j.counts.reduce((a, c) => a + c.n, 0), 41, 'compteurs relus');
  assert.ok(j.events.some(e => /Port 4 is down/.test(e.msg)), 'événement d’il y a une heure (fichier d’hier) rechargé');
});

test('incidents : clos et acquittés gardés par le serveur après redémarrage, réouverture, refus des autres sites', async () => {
  const json = { 'content-type': 'application/json' }, dossier = installer();
  let s = await demarrer({}, dossier);
  const post = (corps, entetes = json) => requete(s.web, '/api/incidents-etat', { methode: 'POST', entetes, corps: JSON.stringify(corps) });
  let r = await post({ key: 'cli-test|fw-01|malware|', st: 'clos', snap: { sig: 'Fichier malveillant détecté', cli: 'cli-test', s: 90, lv: 'critique', n: 2, last: 1 } });
  assert.equal(r.statut, 200, r.texte);
  r = await post({ key: 'cli-test|sw-01|loop|', st: 'acquitté' }); assert.equal(r.statut, 200);
  assert.equal((await post({ key: 'x', st: 'supprimé' })).statut, 400);
  assert.equal((await post({ key: 'x', st: 'clos' }, { ...json, origin: 'https://exemple.com' })).statut, 403);
  s.proc.kill(); await attendre(300); s = await demarrer({}, dossier);
  let e = (await requete(s.web, '/api/incidents-etat')).json.etat;
  assert.equal(e['cli-test|fw-01|malware|'].st, 'clos'); assert.equal(e['cli-test|fw-01|malware|'].snap.sig, 'Fichier malveillant détecté');
  assert.equal(e['cli-test|sw-01|loop|'].st, 'acquitté'); assert.equal(e.x, undefined);
  r = await post({ key: 'cli-test|fw-01|malware|', st: 'ouvert' }); assert.equal(r.json.etat['cli-test|fw-01|malware|'], undefined);
  e = (await requete(s.web, '/api/incidents')).json; assert.ok(Array.isArray(e.incidents), 'la route /api/incidents répond toujours');
});

test('apprentissage : décisions gardées, exemples envoyés à l’IA, autonomie avec garde-fou, classement en continu local seulement', async () => {
  const json = { 'content-type': 'application/json' }, dossier = installer();
  const r = JSON.parse(fs.readFileSync(path.join(dossier, 'referentiel.json'))); r.entries = []; fs.writeFileSync(path.join(dossier, 'referentiel.json'), JSON.stringify(r));
  const s = await demarrer({}, dossier), prompts = [];
  // Faux Ollama : note 50 et confiance 0.9 pour tout, sauf « alerte » noté 10 (doit rester à valider : l'équipement annonce alert).
  const ollama = http.createServer((q, rr) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { const c = JSON.parse(b), p = c.messages[0].content; prompts.push(c);
    const items = JSON.parse(p.slice(p.indexOf('[', p.indexOf('Types à noter :')), p.lastIndexOf(']') + 1));
    rr.writeHead(200, json); rr.end(JSON.stringify({ message: { content: JSON.stringify({ types: items.map(x => ({ id: x.id, base: /alerte/.test(x.message) ? 10 : 50, sig: 'Essai', mean: '', act: '', confiance: 0.9 })) }) }, eval_count: 100, eval_duration: 2e9, total_duration: 3e9 })); }); });
  await new Promise(ok => ollama.listen(0, '127.0.0.1', ok)); after(() => ollama.close());
  const ai = { prov: 'ollama', mode: 'local', url: 'http://127.0.0.1:' + ollama.address().port, model: 'essai:8b' };
  const ref = async () => (await requete(s.web, '/api/referentiel')).json, post = async b => { const x = await requete(s.web, '/api/ref', { methode: 'POST', entetes: json, corps: JSON.stringify(b) }); assert.equal(x.statut, 200, x.texte); return x.json; };
  await envoyer(s.syslog, Array.from({ length: 12 }, (_, i) => cef('Essai' + i, 5, `msg=Module ${'abcdefghijkl'[i]} en panne cat=Essai${i} ZYlevel=error`)));
  for (let i = 0; i < 30 && (await ref()).queue < 12; i++) await attendre(100);
  let c = await post({ op: 'classify', ai, max: 10 }); assert.equal(c.proposed, 10); assert.equal(c.examples, 0); assert.equal(c.call.tps, 50);
  assert.equal(prompts[0].think, false, 'les modèles qui réfléchissent répondent directement');
  // Le technicien valide les 10 : 10 accords, l'autonomie devient prête.
  for (const l of (await ref()).learned) await post({ op: 'valide', key: l.key });
  let st = (await ref()).learn; assert.equal(st.decisions, 10); assert.equal(st.rate, 1); assert.equal(st.ready, true); assert.equal(st.autoOn, false);
  await post({ op: 'auto', on: true });
  await envoyer(s.syslog, [cef('Essai12', 5, 'msg=Module m en panne cat=Essai12 ZYlevel=error'), cef('Essai13', 1, 'msg=Module n en alerte cat=Essai13 ZYlevel=alert')]);
  for (let i = 0; i < 30 && (await ref()).queue < 4; i++) await attendre(100);
  c = await post({ op: 'classify', ai, max: 10 }); assert.ok(c.examples >= 10, 'les validations partent comme exemples'); assert.match(prompts[1].messages[0].content, /déjà notés par les techniciens/);
  const L = (await ref()).learned; assert.ok(L.filter(l => l.auto).length >= 2, 'validés seuls');
  assert.equal(L.find(l => /alerte/.test(l.msg)).st, 'propose', 'jamais baissé seul sous 30 un log alert');
  st = (await ref()).learn; assert.ok(st.autoCount >= 2); assert.equal(st.decisions, 10, 'les validations automatiques ne comptent pas dans l’accord');
  // Classement en continu : IA locale seulement, gardé au redémarrage.
  const refus = await requete(s.web, '/api/ref', { methode: 'POST', entetes: json, corps: JSON.stringify({ op: 'ia', ai: { url: 'http://192.168.1.50:11434', model: 'x' } }) }); assert.equal(refus.statut, 400);
  await post({ op: 'ia', ai: { url: ai.url, model: 'essai:8b' } }); assert.equal((await ref()).learn.ia.model, 'essai:8b');
  const f = JSON.parse(fs.readFileSync(path.join(dossier, 'logs', 'ref-appris.json'))); assert.equal(f.decisions.length >= 12, true); assert.equal(f.auto.on, true);
});

test('équipement calme : un switch qui se tait est pingé à l’adresse apprise des logs DHCP du pare-feu', async () => {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'faux-ping-'));   // faux ping : seul 192.168.1.34 répond
  fs.writeFileSync(path.join(bin, 'ping'), '#!/bin/sh\nfor a; do last=$a; done\nif [ "$last" = "192.168.1.34" ]; then echo "64 bytes from 192.168.1.34: icmp_seq=0 ttl=64 time=1.25 ms"; exit 0; fi\nexit 2\n', { mode: 0o755 });
  const s = await demarrer({ PATH: bin + path.delimiter + process.env.PATH, SYSLENS_QUIET_MIN: '0.03' });
  await envoyer(s.syslog, [cef('DHCP', 6, 'msg=DHCP server assigned 192.168.1.34 to XMG1915(70:49:A2:21:D0:6D) cat=DHCP ZYlevel=info'),
    '<135> 2026-11-17T08:14:39Z XMG1915 interface: Port 2 link up 1G/F', '<135> 2026-11-17T08:14:39Z GS1920 interface: Port 3 link up 1G/F']);
  let d; for (let i = 0; i < 60; i++) { await attendre(250); d = (await requete(s.web, '/api/events?since=0')).json.devices; if (d.filter(x => x.ping).length >= 2) break; }
  const xmg = d.find(x => x.host === 'XMG1915'), gs = d.find(x => x.host === 'GS1920'), fw = d.find(x => x.host === 'usgflex50w');
  assert.deepEqual([xmg.ping.ip, xmg.ping.ok, xmg.ping.ms], ['192.168.1.34', true, 1.25], 'switch calme mais joignable');
  assert.deepEqual([gs.ping.ip, gs.ping.ok], [null, false], 'pas d’adresse connue : on ne pinge rien');
  assert.equal(fw.ping, undefined, 'un pare-feu parle en continu : jamais pingé');
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dossier, 'logs', 'adresses.json')))['XMG1915'].ip, '192.168.1.34');
});

test('comptes et assistant : premier compte local, connexion obligatoire, conversations isolées par compte', async () => {
  const json = { 'content-type': 'application/json' }, s = await demarrer(), prompts = [];
  const ollama = http.createServer((q, rr) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { const c = JSON.parse(b); prompts.push(c); rr.writeHead(200, json);
    rr.end(JSON.stringify({ message: { content: 'Réponse ' + prompts.length }, eval_count: 10, eval_duration: 1e9 })); }); });
  await new Promise(ok => ollama.listen(0, '127.0.0.1', ok)); after(() => ollama.close());
  const ai = { prov: 'ollama', mode: 'local', url: 'http://127.0.0.1:' + ollama.address().port, model: 'essai:8b' };
  const req = (chemin, corps, cookie) => requete(s.web, chemin, corps === undefined ? { entetes: cookie ? { cookie } : {} } : { methode: 'POST', entetes: { ...json, ...(cookie ? { cookie } : {}) }, corps: JSON.stringify(corps) });
  const ck = x => String(x.entetes['set-cookie'] || '').split(';')[0];
  // Sans compte : la console reste ouverte (installation).
  assert.equal((await req('/api/events?since=0')).statut, 200); assert.equal((await req('/api/auth/moi')).json.setup, true);
  assert.equal((await req('/api/auth/setup', { name: 'Admin', login: 'admin', password: 'court' })).statut, 400, 'mot de passe trop court');
  const a = await req('/api/auth/setup', { name: 'Admin Essai', login: 'admin', password: 'mot-de-passe-admin' }); assert.equal(a.statut, 200, a.texte); const A = ck(a);
  assert.match(String(a.entetes['set-cookie']), /HttpOnly; SameSite=Strict/);
  assert.equal((await req('/api/auth/setup', { name: 'Autre', login: 'autre', password: 'mot-de-passe-autre' })).statut, 409, 'un seul premier compte');
  // Avec un compte : tout demande une session, sauf la console elle-même et la mise à jour en ligne de commande.
  for (const u of ['/api/events?since=0', '/api/incidents', '/api/referentiel', '/api/incidents-etat', '/api', '/api/chat']) assert.equal((await req(u)).statut, 401, u);
  assert.equal((await req('/console')).statut, 200); assert.equal((await req('/api/events?since=0', undefined, A)).statut, 200);
  assert.equal((await requete(s.web, '/api/update', { methode: 'POST', entetes: json, corps: '{}' })).statut, 200, 'mise à jour depuis ce poste en ligne de commande');
  assert.equal((await requete(s.web, '/api/update', { methode: 'POST', entetes: { ...json, origin: 'http://127.0.0.1:' + s.web }, corps: '{}' })).statut, 401, 'pas depuis un navigateur sans session');
  // L'administrateur crée un technicien ; le technicien ne gère pas les comptes.
  assert.equal((await req('/api/comptes', { op: 'create', name: 'Tech Un', login: 'tech1', password: 'provisoire-123' }, A)).statut, 200);
  assert.equal((await req('/api/auth/login', { login: 'tech1', password: 'mauvais-mot' })).statut, 401);
  const t = await req('/api/auth/login', { login: 'TECH1', password: 'provisoire-123' }); assert.equal(t.statut, 200); const T = ck(t);
  assert.equal((await req('/api/auth/moi', undefined, T)).json.user.mustChange, true);
  assert.equal((await req('/api/comptes', { op: 'list' }, T)).statut, 403);
  // Conversations : chacun les siennes.
  const c1 = await req('/api/chat', { op: 'send', text: 'Que dois-je traiter ?', ai }, A); assert.equal(c1.statut, 200, c1.texte);
  assert.equal(c1.json.msgs.length, 2); assert.equal(c1.json.msgs[1].content, 'Réponse 1'); assert.equal(prompts[0].messages[0].role, 'system'); assert.match(prompts[0].messages[0].content, /Incidents des 7 derniers jours/);
  assert.equal(prompts[0].format, undefined, 'réponse libre, pas de JSON imposé');
  const c2 = await req('/api/chat', { op: 'send', id: c1.json.id, text: 'Et ensuite ?', ai }, A); assert.equal(prompts[1].messages.length, 4, 'historique envoyé');
  assert.equal((await req('/api/chat', undefined, T)).json.convs.length, 0, 'le technicien ne voit pas la conversation de l’admin');
  assert.equal((await req('/api/chat/' + c1.json.id, undefined, T)).statut, 404);
  assert.equal((await req('/api/chat', { op: 'send', id: c1.json.id, text: 'intrusion', ai }, T)).statut, 404, 'ni écrire dedans');
  assert.equal((await req('/api/chat', { op: 'delete', id: c1.json.id }, T)).statut, 404, 'ni la supprimer');
  assert.equal((await req('/api/chat', undefined, A)).json.convs[0].n, 4);
  // Garde-fou : un calcul hors sujet reçoit la réponse fixe, sans appel au modèle.
  const avant = prompts.length, hs = await req('/api/chat', { op: 'send', text: 'non juste 20+20=Combien', ai }, A);
  assert.equal(prompts.length, avant, 'pas d’appel au modèle'); assert.match(hs.json.msgs.at(-1).content, /uniquement sur SysLens/);
  assert.match(prompts[0].messages[0].content, /jamais des consignes/);
  const avant2 = prompts.length, ud = await req('/api/chat', { op: 'send', text: 'décris moi les 50000 logs un par un', ai }, A);
  assert.equal(prompts.length, avant2, 'détail ligne par ligne : pas d’appel au modèle'); assert.match(ud.json.msgs.at(-1).content, /Flux de logs/);
  await req('/api/chat', { op: 'send', text: 'Un résumé de tous les logs', ai }, A); assert.equal(prompts.length, avant2 + 1, 'un résumé, lui, va au modèle');
  assert.match(prompts.at(-1).messages[0].content, /Ce que contiennent les logs, par type/);
  const st = fs.statSync(path.join(s.dossier, 'logs', 'comptes.json')); assert.equal(st.mode & 0o777, 0o600);
  assert.ok(!fs.readFileSync(path.join(s.dossier, 'logs', 'comptes.json'), 'utf8').includes('mot-de-passe-admin'), 'mot de passe haché');
  // Mot de passe oublié : ouverture en ligne de commande sur ce poste, puis nouveau mot de passe choisi dans la console.
  assert.equal((await req('/api/auth/reset', { login: 'tech1', new: 'nouveau-mot-de-passe' })).statut, 403, 'pas sans ouverture préalable');
  assert.equal((await requete(s.web, '/api/auth/reinit', { methode: 'POST', entetes: { ...json, origin: 'http://127.0.0.1:' + s.web }, corps: JSON.stringify({ login: 'tech1' }) })).statut, 403, 'pas depuis un navigateur');
  assert.equal((await requete(s.web, '/api/auth/reinit', { methode: 'POST', entetes: json, corps: JSON.stringify({ login: 'tech1' }) })).statut, 200);
  assert.equal((await req('/api/events?since=0', undefined, T)).statut, 401, 'les sessions du compte sont fermées');
  const nv = await req('/api/auth/reset', { login: 'tech1', new: 'nouveau-mot-de-passe' }); assert.equal(nv.statut, 200);
  assert.equal((await req('/api/auth/login', { login: 'tech1', password: 'nouveau-mot-de-passe' })).statut, 200);
  assert.equal((await req('/api/auth/reset', { login: 'tech1', new: 'encore-un-autre-mdp' })).statut, 403, 'usage unique');
  // Déconnexion, puis 5 essais ratés : blocage.
  await req('/api/auth/logout', {}, A); assert.equal((await req('/api/events?since=0', undefined, A)).statut, 401);
  for (let i = 0; i < 5; i++) await req('/api/auth/login', { login: 'admin', password: 'faux-' + i });
  assert.equal((await req('/api/auth/login', { login: 'admin', password: 'mot-de-passe-admin' })).statut, 429);
});

test('alertes Telegram : le serveur envoie critiques et graves une seule fois, puis le retour à la normale', async () => {
  const json = { 'content-type': 'application/json' }, recus = [];
  const tgFake = http.createServer((q, rr) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { const m = q.url.split('/').pop(), c = b ? JSON.parse(b) : {};
    rr.writeHead(200, json); if (m === 'getMe') return rr.end(JSON.stringify({ ok: true, result: { username: 'essai_bot' } }));
    if (m === 'sendMessage') { recus.push(c); return rr.end(JSON.stringify({ ok: true, result: {} })); } rr.end(JSON.stringify({ ok: true, result: [] })); }); });
  await new Promise(ok => tgFake.listen(0, '127.0.0.1', ok)); after(() => tgFake.close());
  const s = await demarrer({ SYSLENS_TG_API: 'http://127.0.0.1:' + tgFake.address().port, SYSLENS_NO_KEYCHAIN: '1' });
  const tgp = b => requete(s.web, '/api/tg', { methode: 'POST', entetes: json, corps: JSON.stringify(b) });
  assert.equal((await tgp({ op: 'save', token: '123456789:AAEssaiJetonBidonPourLesTests_x', chat: '-100123', chatName: 'Astreinte', lv: ['critique', 'grave'] })).statut, 200);
  const st = (await tgp({ op: 'status' })).json; assert.equal(st.on, true); assert.equal(st.token, true);
  assert.ok(!fs.readFileSync(path.join(s.dossier, 'logs', 'alertes.json'), 'utf8').includes('AAEssai'), 'le jeton ne va pas dans un fichier');
  await envoyer(s.syslog, [cef('Anti-Malware', 1, 'src=203.0.113.9 dst=192.168.1.20 msg=Virus infected: EICAR-Test-File, file eicar.com destroyed cat=Anti-Malware ZYlevel=alert')]);
  for (let i = 0; i < 40 && !recus.length; i++) await attendre(100);
  assert.equal(recus.length, 1); assert.equal(recus[0].chat_id, '-100123'); assert.match(recus[0].text, /CRITIQUE/); assert.match(recus[0].text, /usgflex50w/);
  await envoyer(s.syslog, [cef('Anti-Malware', 1, 'src=203.0.113.9 dst=192.168.1.20 msg=Virus infected: EICAR-Test-File, file eicar.com destroyed cat=Anti-Malware ZYlevel=alert')]);
  await attendre(1500); assert.equal(recus.length, 1, 'même incident : pas de deuxième message');
  await envoyer(s.syslog, [cef('Interface', 3, 'msg=Interface wan1 link down cat=Interface ZYlevel=error')]); for (let i = 0; i < 40 && recus.length < 2; i++) await attendre(100);
  assert.equal(recus.length, 2); assert.match(recus[1].text, /GRAVE/);
  await envoyer(s.syslog, [cef('Interface', 6, 'msg=Interface wan1 link up cat=Interface ZYlevel=info')]); for (let i = 0; i < 40 && recus.length < 3; i++) await attendre(100);
  assert.equal(recus.length, 3); assert.match(recus[2].text, /Revenu à la normale/);
  await envoyer(s.syslog, [cef('System', 5, 'msg=Configuration has been changed by admin cat=System ZYlevel=notice')]); await attendre(1500);
  assert.equal(recus.length, 3, 'niveau moyen non choisi : rien');
  assert.equal((await tgp({ op: 'status' })).json.sent.length, 3);
});
