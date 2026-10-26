const http = require('http');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn, execFile } = require('child_process');

const DATA_DIR = process.env.DATA_DIR || '/data';
const WEB_PORT = Number(process.env.WEB_PORT || 3001);
const PROXY_PORT = Number(process.env.PROXY_PORT || 1080);
const PUBLIC_PROXY_PORT = Number(process.env.PUBLIC_PROXY_PORT || 20180);
const SOCKS_PORT = Number(process.env.SOCKS_PORT || 1081);
const HTTP_PORT = Number(process.env.HTTP_PORT || 1082);

const STATE_FILE = path.join(DATA_DIR, 'state.json');
const XRAY_CONFIG = path.join(DATA_DIR, 'xray.json');
const INDEX_FILE = path.join(__dirname, 'public', 'index.html');
const MAX_LOG = 200;

let state = { link: '' };
let child = null;
let childStartedAt = 0;
let lastError = '';
let logs = [];
let xrayVersion = '';
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
  const pqv = q.get('pqv') || '';
  const spx = q.get('spx') || '';
  const encryption = q.get('encryption') || 'none';
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
    pqv,
    spx,
    encryption,
    alpn,
    allowInsecure,
    name,
  };
  parsed.outbound = buildOutbound(parsed);
  return parsed;
}

function buildOutbound(p) {
  const user = { id: p.uuid, encryption: p.encryption || 'none' };
  if (p.flow) user.flow = p.flow;
  const stream = { network: p.network === 'h2' ? 'http' : p.network || 'tcp' };
  if (p.security === 'tls') {
    stream.security = 'tls';
    stream.tlsSettings = {
      serverName: p.sni,
      fingerprint: p.fp || 'chrome',
      allowInsecure: !!p.allowInsecure,
    };
    if (p.alpn.length) stream.tlsSettings.alpn = p.alpn;
  } else if (p.security === 'reality') {
    if (!p.pbk) throw new Error('Для reality нужен параметр pbk');
    stream.security = 'reality';
    stream.realitySettings = {
      serverName: p.sni,
      fingerprint: p.fp || 'chrome',
      publicKey: p.pbk,
      shortId: p.sid,
      spiderX: p.spx || '/',
    };
    if (p.pqv) stream.realitySettings.mldsa65Verify = p.pqv;
  } else if (p.security !== 'none' && p.security !== '') {
    throw new Error('Тип безопасности «' + p.security + '» не поддерживается');
  }
  switch (p.network) {
    case 'tcp':
    case 'raw':
    case '':
      break;
    case 'ws':
      stream.wsSettings = { path: p.path };
      if (p.host) stream.wsSettings.headers = { Host: p.host };
      break;
    case 'grpc':
      stream.grpcSettings = { serviceName: p.serviceName };
      if (p.grpcMode === 'multi') stream.grpcSettings.multiMode = true;
      break;
    case 'http':
    case 'h2':
      stream.httpSettings = { host: [p.host || p.sni || p.server], path: p.path };
      break;
    case 'httpupgrade':
      stream.httpupgradeSettings = { host: p.host || p.sni || p.server, path: p.path };
      break;
    default:
      throw new Error('Транспорт «' + p.network + '» не поддерживается');
  }
  return {
    tag: 'proxy',
    protocol: 'vless',
    settings: { vnext: [{ address: p.server, port: p.port, users: [user] }] },
    streamSettings: stream,
  };
}

function buildConfig(parsed) {
  const privateRanges = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '::1/128',
    'fc00::/7',
    'fe80::/10',
  ];
  return {
    log: { loglevel: 'info' },
    inbounds: [
      {
        tag: 'socks-in',
        listen: '127.0.0.1',
        port: SOCKS_PORT,
        protocol: 'socks',
        settings: { auth: 'noauth', udp: false },
      },
      {
        tag: 'http-in',
        listen: '127.0.0.1',
        port: HTTP_PORT,
        protocol: 'http',
        settings: {},
      },
    ],
    outbounds: [parsed.outbound, { tag: 'direct', protocol: 'freedom' }],
    routing: {
      domainStrategy: 'AsIs',
      rules: [{ type: 'field', ip: privateRanges, outboundTag: 'direct' }],
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
    execFile('xray', ['run', '-test', '-config', XRAY_CONFIG], { timeout: 15000 }, (err, stdout, stderr) => {
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
  fs.writeFileSync(XRAY_CONFIG, JSON.stringify(buildConfig(parsed), null, 2));
  const check = await checkConfig();
  if (!check.ok) {
    lastError = check.error || 'Xray отверг конфигурацию';
    addLog('[config] ' + lastError);
    return;
  }
  lastError = '';
  const proc = spawn('xray', ['run', '-config', XRAY_CONFIG], {
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
        lastError = 'Xray завершился с кодом ' + code;
      } else if (signal) {
        lastError = 'Xray остановлен (' + signal + ')';
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
    const host = 'api.ipify.org';
    let settled = false;
    let socket = null;
    let secure = null;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      if (secure) secure.destroy();
      if (socket) socket.destroy();
      resolve(Object.assign({ ms: Date.now() - started }, payload));
    };
    socket = net.connect(PROXY_PORT, '127.0.0.1');
    socket.setTimeout(15000);
    socket.once('timeout', () => finish({ ok: false, error: 'Таймаут через прокси' }));
    socket.once('error', (err) => finish({ ok: false, error: err.code || err.message }));
    socket.once('connect', () => {
      socket.write('CONNECT ' + host + ':443 HTTP/1.1\r\nHost: ' + host + ':443\r\nProxy-Connection: keep-alive\r\n\r\n');
      let head = Buffer.alloc(0);
      const onData = (chunk) => {
        head = Buffer.concat([head, chunk]);
        const idx = head.indexOf('\r\n\r\n');
        if (idx < 0) {
          if (head.length > 8192) finish({ ok: false, error: 'Некорректный ответ прокси' });
          return;
        }
        socket.removeListener('data', onData);
        const statusLine = head.slice(0, idx).toString('utf8').split('\r\n')[0] || '';
        const code = Number((statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})/) || [])[1]);
        if (code !== 200) {
          finish({ ok: false, status: code || null, error: 'Прокси ответил ' + (code || '?') });
          return;
        }
        secure = tls.connect({ socket, servername: host }, () => {
          secure.write('GET / HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: vless-proxy\r\nConnection: close\r\n\r\n');
        });
        secure.setTimeout(15000);
        secure.once('timeout', () => finish({ ok: false, error: 'Таймаут TLS' }));
        secure.once('error', (err) => finish({ ok: false, error: err.code || err.message }));
        let buf = '';
        secure.on('data', (part) => {
          buf += part.toString('utf8');
          if (buf.length > 8192) secure.destroy();
        });
        secure.on('end', () => {
          const parts = buf.split('\r\n\r\n');
          const status = Number(((parts[0] || '').match(/^HTTP\/1\.[01]\s+(\d{3})/) || [])[1]);
          const text = (parts.slice(1).join('\r\n\r\n') || '').trim();
          const ip = text.split(/\s+/).find((word) => /^[0-9a-fA-F:.]{3,64}$/.test(word)) || '';
          finish({ ok: status === 200 && !!ip, status: status || null, ip: ip || null });
        });
      };
      socket.on('data', onData);
    });
  });
}

let muxServer = null;

function startMux() {
  if (muxServer) return;
  muxServer = net.createServer((client) => {
    const timer = setTimeout(() => client.destroy(), 10000);
    client.once('data', (chunk) => {
      clearTimeout(timer);
      client.pause();
      const target = chunk[0] === 0x05 || chunk[0] === 0x04 ? SOCKS_PORT : HTTP_PORT;
      const upstream = net.connect(target, '127.0.0.1');
      upstream.once('connect', () => {
        upstream.write(chunk);
        client.pipe(upstream);
        upstream.pipe(client);
        client.resume();
      });
      upstream.once('error', () => client.destroy());
      client.once('error', () => upstream.destroy());
    });
    client.once('error', () => {});
  });
  muxServer.on('error', (err) => addLog('[mux] ' + (err.code || err.message)));
  muxServer.listen(PROXY_PORT, '0.0.0.0', () => {
    addLog('[mux] 0.0.0.0:' + PROXY_PORT + ' → socks ' + SOCKS_PORT + ' / http ' + HTTP_PORT);
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
    version: xrayVersion,
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
  execFile('xray', ['version'], { timeout: 5000 }, (err, stdout, stderr) => {
    const text = (stdout || stderr || '').trim();
    if (!err && text) {
      xrayVersion = ((text.match(/Xray\s+(\S+)/i) || [])[1] || '').trim();
    }
  });
}

async function boot() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  detectVersion();
  startMux();
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
    if (muxServer) muxServer.close();
    process.exit(0);
  });
}

boot();
