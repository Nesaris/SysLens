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
      let b = ''; r.on('data', d => b += d); r.on('end', () => { let json = null; try { json = JSON.parse(b); } catch (e) {} ok({ statut: r.statusCode, json, texte: b }); });
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
