const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn, execFile } = require('child_process');

const DATA_DIR = process.env.DATA_DIR || '/data';
const WEB_PORT = Number(process.env.WEB_PORT || 3001);
const PROXY_PORT = Number(process.env.PROXY_PORT || 1080);
const PUBLIC_PROXY_PORT = Number(process.env.PUBLIC_PROXY_PORT || 20180);

const STATE_FILE = path.join(DATA_DIR, 'state.json');
const SB_CONFIG = path.join(DATA_DIR, 'sing-box.json');
const INDEX_FILE = path.join(__dirname, 'public', 'index.html');
const MAX_LOG = 200;

let state = { link: '' };
let child = null;
let childStartedAt = 0;
let lastError = '';
let logs = [];
let singboxVersion = '';
let switching = Promise.resolve();

function addLog(text) {
  const lines = String(text).split('\n').filter(Boolean);
  for (const line of lines) {
    logs.push({ t: Date.now(), line });
  }
  if (logs.length > MAX_LOG) logs = logs.slice(-MAX_LOG);
}

function loadState() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (raw && typeof raw.link === 'string') state = { link: raw.link };
  } catch {}
}

function saveState() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function decodeSubscription(input) {
  const text = String(input || '').trim();
  if (/^vless:\/\//i.test(text)) return text;
  const compact = text.replace(/\s+/g, '');
  if (!compact) throw new Error('Пустая ссылка');
  let decoded = '';
  try {
    decoded = Buffer.from(compact, 'base64').toString('utf8');
  } catch {
    throw new Error('Нужна ссылка vless:// или base64-подписка');
  }
  const found = decoded.split(/\r?\n/).map((s) => s.trim()).find((s) => /^vless:\/\//i.test(s));
  if (!found) throw new Error('В подписке не найдена VLESS-ссылка');
  return found;
}

function normalizePublicKey(value) {
  const raw = String(value || '').trim().replace(/\s+/g, '');
  if (!raw) return '';
  const base = raw.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]+$/.test(base)) throw new Error('Параметр pbk повреждён');
  if (base.length < 40) throw new Error('Параметр pbk слишком короткий');
  return base.replace(/\+/g, '-').replace(/\//g, '_');
}

function parseVless(input) {
  const link = decodeSubscription(input);
  let u;
  try {
    u = new URL(link);
  } catch {
    throw new Error('Не удалось разобрать ссылку');
  }
  if (u.protocol !== 'vless:') throw new Error('Поддерживается только VLESS');
  const uuid = decodeURIComponent(u.username || '');
  if (!uuid) throw new Error('В ссылке нет UUID');
  const server = u.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (!server) throw new Error('В ссылке нет адреса сервера');
  const port = Number(u.port || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Некорректный порт');
  const q = u.searchParams;
  const security = (q.get('security') || 'none').toLowerCase();
  const network = (q.get('type') || 'tcp').toLowerCase();
  const flow = q.get('flow') || '';
  const hostHeader = q.get('host') || '';
  const sni = q.get('sni') || hostHeader || server;
  const rawPath = q.get('path') || '/';
  const serviceName = q.get('serviceName') || q.get('service_name') || '';
  const grpcMode = q.get('mode') || '';
  const fp = q.get('fp') || '';
  const pbk = normalizePublicKey(q.get('pbk') || '');
  const sid = q.get('sid') || '';
  const alpn = (q.get('alpn') || '').split(',').map((s) => s.trim()).filter(Boolean);
  const allowInsecure = ['1', 'true', 'yes'].includes((q.get('allowInsecure') || q.get('insecure') || '').toLowerCase());
  const name = decodeURIComponent((u.hash || '').replace(/^#/, ''));
  const parsed = {
    link,
    uuid,
    server,
    port,
    security,
    network,
    flow,
    host: hostHeader,
    sni,
    path: rawPath.startsWith('/') ? rawPath : '/' + rawPath,
    serviceName,
    grpcMode,
    fp,
    pbk,
    sid,
    alpn,
    allowInsecure,
    name,
  };
  parsed.outbound = buildOutbound(parsed);
  return parsed;
}

function buildOutbound(p) {
  const outbound = {
    type: 'vless',
    tag: 'proxy',
    server: p.server,
    server_port: p.port,
    uuid: p.uuid,
  };
  if (p.flow) outbound.flow = p.flow;
  if (p.security === 'tls' || p.security === 'reality') {
    outbound.tls = {
      enabled: true,
      server_name: p.sni,
      insecure: p.allowInsecure,
    };
    if (p.alpn.length) outbound.tls.alpn = p.alpn;
    outbound.tls.utls = {
      enabled: true,
      fingerprint: p.fp || 'chrome',
    };
    if (p.security === 'reality') {
      if (!p.pbk) throw new Error('Для reality нужен параметр pbk');
      outbound.tls.reality = {
        enabled: true,
        public_key: p.pbk,
        short_id: p.sid,
      };
    }
  }
  switch (p.network) {
    case 'tcp':
    case '':
      break;
    case 'ws':
      outbound.transport = { type: 'ws', path: p.path };
      if (p.host) outbound.transport.headers = { Host: p.host };
      break;
    case 'grpc':
      outbound.transport = { type: 'grpc', service_name: p.serviceName };
      break;
    case 'http':
    case 'h2':
      outbound.transport = { type: 'http', host: [p.host || p.server], path: p.path };
      break;
    case 'httpupgrade':
      outbound.transport = { type: 'httpupgrade', host: p.host || p.server, path: p.path };
      break;
    default:
      throw new Error('Транспорт «' + p.network + '» не поддерживается');
  }
  return outbound;
}

function buildConfig(parsed) {
  return {
    log: { level: 'info', timestamp: true },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '0.0.0.0',
        listen_port: PROXY_PORT,
      },
    ],
    outbounds: [
      parsed.outbound,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      rules: [
        { ip_is_private: true, outbound: 'direct' },
      ],
      final: 'proxy',
    },
  };
}

function summary(parsed) {
  if (!parsed) return null;
  return {
    server: parsed.server,
    port: parsed.port,
    security: parsed.security,
    network: parsed.network,
    sni: parsed.sni,
    path: parsed.path,
    flow: parsed.flow || null,
    name: parsed.name || null,
    uuidMasked: parsed.uuid.slice(0, 8) + '…' + parsed.uuid.slice(-4),
  };
}

function safeParse(link) {
  if (!link) return null;
  try {
    return parseVless(link);
  } catch {
    return null;
  }
}

function checkConfig() {
  return new Promise((resolve) => {
    execFile('sing-box', ['check', '-c', SB_CONFIG], { timeout: 15000 }, (err, stdout, stderr) => {
      if (err) {
        resolve({ ok: false, error: (stderr || stdout || err.message).trim() });
      } else {
        resolve({ ok: true, error: '' });
      }
    });
  });
}

function stopChild() {
  if (!child) return Promise.resolve();
  const proc = child;
  child = null;
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    proc.once('exit', finish);
    try {
      proc.kill('SIGTERM');
    } catch {
      finish();
      return;
    }
    setTimeout(() => {
      try {
        proc.kill('SIGKILL');
      } catch {}
      finish();
    }, 4000);
  });
}

async function startChild() {
  if (!state.link) return;
  let parsed;
  try {
    parsed = parseVless(state.link);
  } catch (err) {
    lastError = err.message;
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(SB_CONFIG, JSON.stringify(buildConfig(parsed), null, 2));
  const check = await checkConfig();
  if (!check.ok) {
    lastError = check.error || 'sing-box отверг конфигурацию';
    addLog('[config] ' + lastError);
    return;
  }
  lastError = '';
  const proc = spawn('sing-box', ['run', '-c', SB_CONFIG], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child = proc;
  childStartedAt = Date.now();
  proc.stdout.on('data', (d) => addLog(d.toString()));
  proc.stderr.on('data', (d) => addLog(d.toString()));
  proc.on('error', (err) => {
    lastError = err.message;
    addLog('[spawn] ' + err.message);
  });
  proc.on('exit', (code, signal) => {
    if (child === proc) {
      child = null;
      if (code !== 0 && code !== null) {
        lastError = 'sing-box завершился с кодом ' + code;
      } else if (signal) {
        lastError = 'sing-box остановлен (' + signal + ')';
      }
      addLog('[exit] code=' + code + ' signal=' + signal);
    }
  });
}

function restart() {
  switching = switching.then(async () => {
    await stopChild();
    await startChild();
  }).catch((err) => {
    lastError = err.message;
  });
  return switching;
}

function tcpCheck(parsed) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect(parsed.port, parsed.server);
    let settled = false;
    const finish = (ok, error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ok, ms: Date.now() - started, error: error || null });
    };
    socket.setTimeout(6000);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'Таймаут подключения'));
    socket.once('error', (err) => finish(false, err.code || err.message));
  });
}

function egressCheck() {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect(PROXY_PORT, '127.0.0.1');
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(Object.assign({ ms: Date.now() - started }, payload));
    };
    socket.setTimeout(15000);
    socket.once('timeout', () => finish({ ok: false, error: 'Таймаут через прокси' }));
    socket.once('error', (err) => finish({ ok: false, error: err.code || err.message }));
    socket.once('connect', () => {
      const req = http.request({
        host: 'api.ipify.org',
        port: 80,
        method: 'GET',
        path: 'http://api.ipify.org/',
        headers: { Host: 'api.ipify.org', 'User-Agent': 'vless-proxy' },
        createConnection: () => socket,
      });
      req.setTimeout(15000, () => {
        req.destroy(new Error('timeout'));
      });
      req.on('response', (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 200) req.destroy();
        });
        res.on('end', () => {
          const ip = body.trim();
          finish({ ok: res.statusCode === 200 && !!ip, status: res.statusCode, ip: ip.slice(0, 64) || null });
        });
      });
      req.on('error', (err) => finish({ ok: false, error: err.code || err.message }));
      req.end();
    });
  });
}

function statusPayload() {
  const parsed = safeParse(state.link);
  return {
    configured: !!state.link,
    link: state.link || '',
    parsed: summary(parsed),
    running: !!child,
    pid: child ? child.pid : null,
    uptimeSec: child ? Math.round((Date.now() - childStartedAt) / 1000) : 0,
    error: lastError || null,
    version: singboxVersion,
    proxy: {
      internalPort: PROXY_PORT,
      publicPort: PUBLIC_PROXY_PORT,
    },
    logs: logs.slice(-40),
  };
}

function sendJson(res, code, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 65536) {
        reject(new Error('Слишком большой запрос'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = fs.readFileSync(INDEX_FILE);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' });
      res.end(html);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/health') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/status') {
      sendJson(res, 200, statusPayload());
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/logs') {
      sendJson(res, 200, { logs: logs.slice(-120) });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/link') {
      const raw = await readBody(req);
      let payload;
      try {
        payload = JSON.parse(raw || '{}');
      } catch {
        throw new Error('Некорректный JSON');
      }
      const parsed = parseVless(payload.link || '');
      state = { link: parsed.link };
      saveState();
      addLog('[config] новая ссылка: ' + parsed.server + ':' + parsed.port);
      await restart();
      const fresh = safeParse(state.link);
      const running = !!child;
      const error = lastError || null;
      sendJson(res, 200, { ok: running, parsed: summary(fresh), running, error, status: statusPayload() });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/restart') {
      await restart();
      sendJson(res, 200, { ok: !!child, status: statusPayload() });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/stop') {
      await stopChild();
      lastError = '';
      sendJson(res, 200, { ok: true, status: statusPayload() });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/check') {
      const parsed = safeParse(state.link);
      if (!parsed) throw new Error('Ссылка ещё не задана');
      sendJson(res, 200, await tcpCheck(parsed));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/egress') {
      if (!child) throw new Error('Прокси не запущен');
      sendJson(res, 200, await egressCheck());
      return;
    }
    sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    sendJson(res, 400, { error: err.message || String(err) });
  }
});

function detectVersion() {
  execFile('sing-box', ['version'], { timeout: 5000 }, (err, stdout, stderr) => {
    const text = (stdout || stderr || '').trim();
    if (!err && text) {
      singboxVersion = (text.split('\n')[0] || '').replace(/^sing-box version\s*/i, '').trim();
    }
  });
}

async function boot() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  detectVersion();
  loadState();
  if (state.link) {
    await restart();
  }
  server.listen(WEB_PORT, '0.0.0.0', () => {
    addLog('[web] http://0.0.0.0:' + WEB_PORT);
  });
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, async () => {
    await stopChild();
    process.exit(0);
  });
}

boot();
