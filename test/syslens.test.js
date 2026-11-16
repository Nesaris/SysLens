'use strict';
// Essais de bout en bout : un vrai serveur SysLens, du vrai syslog en UDP, la vraie console HTTP.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process'), dgram = require('node:dgram'), http = require('node:http');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');

const RACINE = path.join(__dirname, '..');
const FICHIERS = ['syslens.js', 'console.html', 'package.json', 'nouveautes.json'];
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
  const dev = (await requete(s.web, '/api/events?since=0')).json.devices;
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
