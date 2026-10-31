'use strict';

/**
 * Samaritan passive RECON service.
 *
 * Deliberately limited to HTTP/TLS inspection and public registry lookups.
 * It does not perform arbitrary port sweeps, brute force, exploitation or
 * credential testing. The service is intended to stay on the private Compose
 * network behind the Next.js validation/rate-limit proxy.
 */
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const dns = require('node:dns').promises;
const net = require('node:net');
const { timingSafeEqual } = require('node:crypto');

const PORT = Number(process.env.SCANNER_PORT || 4000);
const HOST = process.env.SCANNER_HOST || '127.0.0.1';
const KEY = process.env.SCANNER_KEY || '';
const KEY_CONFIGURED = KEY.length >= 32 && KEY.length <= 256 && /^[\x21-\x7e]+$/.test(KEY) && !/^change-this/i.test(KEY);
if (!KEY_CONFIGURED) console.warn('[SAMARITAN SCANNER] SCANNER_KEY must be a unique printable secret of at least 32 characters; scan requests will be rejected.');
const USER_AGENT = 'Samaritan-RECON/1.0 (passive security research)';
const MAX_BODY = 300_000;
const REQUEST_TIMEOUT = 9_000;
const CACHE_TTL = 5 * 60_000;
const cache = new Map();

const BLOCKED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const BLOCKED_V6_PREFIX = [
  '::', '::1', '::ffff:', '64:ff9b::', '64:ff9b:1:', '100::', '2001:db8:',
  'fc', 'fd', 'fe8', 'fe9', 'fea', 'feb', 'fec', 'fed', 'fee', 'fef', 'ff',
];

function ipv4Int(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}
function inV4Range(ip, base, bits) {
  const a = ipv4Int(ip), b = ipv4Int(base);
  if (a === null || b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}
function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return !BLOCKED_V4.some(([base, bits]) => inV4Range(ip, base, bits));
  if (family === 6) {
    const s = ip.toLowerCase();
    if (BLOCKED_V6_PREFIX.some(p => s.startsWith(p))) return false;
    // Only globally routed unicast addresses are accepted.
    return s.startsWith('2') || s.startsWith('3');
  }
  return false;
}

function normalizeTarget(raw) {
  if (typeof raw !== 'string' || raw.length > 260) throw new Error('Target must be a hostname or IP address.');
  let input = raw.trim();
  if (!input) throw new Error('Target is required.');
  if (input.includes('://')) {
    const u = new URL(input);
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Error('Only HTTP and HTTPS targets are allowed.');
    if (u.port && !['80', '443'].includes(u.port)) throw new Error('Only standard web ports are allowed.');
    input = u.hostname;
  } else {
    input = input.replace(/^\[|\]$/g, '');
    if (input.includes('/') || input.includes('@') || input.includes('?') || input.includes('#')) throw new Error('Enter a hostname or IP only.');
    if (input.includes(':') && net.isIP(input) !== 6) throw new Error('Ports are not accepted; enter a hostname or IP only.');
  }
  input = input.replace(/\.$/, '').toLowerCase();
  if (net.isIP(input)) {
    if (!isPublicIp(input)) throw new Error('Private, reserved and non-global IP ranges are blocked.');
    return input;
  }
  if (input.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(input)) {
    throw new Error('Enter a fully qualified public hostname.');
  }
  if (input === 'localhost' || input.endsWith('.localhost') || input.endsWith('.local') || input.endsWith('.internal')) {
    throw new Error('Reserved hostnames are blocked.');
  }
  return input;
}

async function resolvePublic(host) {
  if (net.isIP(host)) return { address: host, family: net.isIP(host) };
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => !isPublicIp(r.address))) throw new Error('The hostname resolves to a private or reserved address.');
  return records[0];
}

function requestPinned(urlString, ipRecord, redirects = 2) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) return reject(new Error('Blocked URL protocol.'));
    if (url.port && !['80', '443'].includes(url.port)) return reject(new Error('Only standard HTTP and HTTPS ports are allowed.'));
    const transport = url.protocol === 'https:' ? https : http;
    const opts = {
      method: 'GET',
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
      headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/json;q=0.9,*/*;q=0.5', 'accept-encoding': 'identity' },
      timeout: REQUEST_TIMEOUT,
      lookup: (_hostname, _options, callback) => callback(null, ipRecord.address, ipRecord.family),
    };
    const req = transport.request(opts, res => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location && redirects > 0) {
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        resolve(next);
        return;
      }
      const chunks = [];
      let length = 0;
      res.on('data', chunk => {
        length += chunk.length;
        if (length <= MAX_BODY) chunks.push(chunk);
        else req.destroy(new Error('Response body exceeded the inspection limit.'));
      });
      res.on('end', () => resolve({
        status,
        statusText: res.statusMessage || '',
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        url: url.toString(),
      }));
    });
    req.on('timeout', () => req.destroy(new Error('Target request timed out.')));
    req.on('error', reject);
    req.end();
  }).then(async result => {
    if (typeof result === 'string') {
      const nextUrl = new URL(result);
      const nextHost = normalizeTarget(nextUrl.hostname);
      const nextIp = await resolvePublic(nextHost);
      return requestPinned(result, nextIp, redirects - 1);
    }
    return result;
  });
}

async function inspectWeb(host) {
  const ip = await resolvePublic(host);
  let result;
  try {
    result = await requestPinned(`https://${host}/`, ip);
  } catch (httpsError) {
    // Only retry plain HTTP when TLS negotiation failed; redirects are still
    // revalidated and DNS-pinned on every hop.
    result = await requestPinned(`http://${host}/`, ip);
  }
  return { ip: ip.address, ...result };
}

function titleFrom(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim().slice(0, 180) : '';
}
function metaGenerator(html) {
  const m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)
    || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
  return m ? m[1].slice(0, 160) : '';
}
function safeHeaders(headers) {
  const allow = ['server', 'date', 'content-type', 'content-length', 'last-modified', 'etag', 'cache-control', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'x-powered-by', 'access-control-allow-origin'];
  const out = {};
  for (const key of allow) if (headers[key] !== undefined) out[key] = String(headers[key]).slice(0, 500);
  return out;
}

async function cached(key, loader) {
  const item = cache.get(key);
  if (item && Date.now() - item.at < CACHE_TTL) return item.value;
  const value = await loader();
  cache.set(key, { at: Date.now(), value });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return value;
}
async function fetchJson(url, timeout = 10_000) {
  const response = await fetch(url, { signal: AbortSignal.timeout(timeout), headers: { 'user-agent': USER_AGENT, accept: 'application/json' }, redirect: 'error' });
  if (!response.ok) throw new Error(`Upstream returned HTTP ${response.status}.`);
  return response.json();
}

async function sslInfo(host) {
  const ip = await resolvePublic(host);
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: ip.address, port: 443,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: REQUEST_TIMEOUT,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
      const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
      const now = Date.now();
      resolve({
        target: host, ip: ip.address, authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        protocol: socket.getProtocol(), cipher: socket.getCipher()?.name || null,
        subject: cert.subject || null, issuer: cert.issuer || null,
        subjectAltName: cert.subjectaltname || null,
        valid_from: validFrom, valid_to: validTo,
        days_remaining: validTo ? Math.floor((Date.parse(validTo) - now) / 86_400_000) : null,
        fingerprint256: cert.fingerprint256 || null, serialNumber: cert.serialNumber || null,
      });
      socket.end();
    });
    socket.setTimeout(REQUEST_TIMEOUT, () => socket.destroy(new Error('TLS handshake timed out.')));
    socket.once('error', reject);
  });
}

async function nvdVulnerabilities(host, info) {
  const tech = [info.headers?.server, info.headers?.['x-powered-by'], metaGenerator(info.body)].filter(Boolean);
  const clean = [...new Set(tech.map(x => String(x).replace(/[^a-zA-Z0-9 ._+-]/g, ' ').trim()).filter(x => x.length >= 3))].slice(0, 2);
  if (!clean.length) return { target: host, software: [], vulnerabilities: [], risk_level: 'UNKNOWN', note: 'No software version was exposed by public HTTP metadata. This is a passive check, not proof that the host is secure.' };
  const rows = [];
  for (const keyword of clean) {
    try {
      const q = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      q.searchParams.set('keywordSearch', keyword);
      q.searchParams.set('resultsPerPage', '8');
      const data = await fetchJson(q.toString(), 12_000);
      for (const item of data.vulnerabilities || []) {
        const cve = item.cve || {};
        const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
        const cvssData = metric?.cvssData || {};
        const severity = String(metric?.baseSeverity || cvssData.baseSeverity || 'UNKNOWN').toUpperCase();
        rows.push({
          id: cve.id,
          severity,
          cvss: cvssData.baseScore,
          type: 'NVD advisory',
          description: (cve.descriptions || []).find(x => x.lang === 'en')?.value?.slice(0, 500) || '',
          observed_software: keyword,
          is_exploit: false,
          verified_match: false,
        });
      }
    } catch { /* NVD quota/outage should not break the passive report. */ }
  }
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  rows.sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0));
  return {
    target: host, software: clean, vulnerabilities: rows.slice(0, 20),
    risk_level: rows.length ? rows[0].severity : 'UNKNOWN',
    note: 'NVD keyword matches are leads only. The service banner does not prove an affected version is installed; verify each advisory manually.',
  };
}

const routes = {
  quick: async host => {
    const d = await cached(`web:${host}`, () => inspectWeb(host));
    return { target: host, ip: d.ip, status: d.status, statusText: d.statusText, title: titleFrom(d.body), server: d.headers.server || null, poweredBy: d.headers['x-powered-by'] || null, headers: safeHeaders(d.headers), finalUrl: d.url, scannedAt: new Date().toISOString() };
  },
  headers: async host => {
    const d = await cached(`web:${host}`, () => inspectWeb(host));
    return { target: host, ip: d.ip, status: d.status, headers: safeHeaders(d.headers), note: 'Only selected response headers are returned; cookies and authentication headers are omitted.' };
  },
  tech: async host => {
    const d = await cached(`web:${host}`, () => inspectWeb(host));
    const items = [];
    if (d.headers.server) items.push({ name: d.headers.server, category: 'Web server', confidence: 'header disclosure' });
    if (d.headers['x-powered-by']) items.push({ name: d.headers['x-powered-by'], category: 'Application runtime', confidence: 'header disclosure' });
    const generator = metaGenerator(d.body);
    if (generator) items.push({ name: generator, category: 'CMS / generator', confidence: 'HTML metadata' });
    if (/__next|_next\//.test(d.body)) items.push({ name: 'Next.js', category: 'Framework', confidence: 'HTML fingerprint' });
    if (/wp-content|wp-includes/.test(d.body)) items.push({ name: 'WordPress', category: 'CMS', confidence: 'HTML fingerprint' });
    if (/cdn\.shopify\.com/.test(d.body)) items.push({ name: 'Shopify', category: 'Commerce', confidence: 'HTML fingerprint' });
    return { target: host, ip: d.ip, technologies: items, count: items.length, note: 'Passive fingerprints only; results are indicative, not definitive.' };
  },
  ssl: sslInfo,
  rdns: async host => {
    const ip = net.isIP(host) ? host : (await resolvePublic(host)).address;
    const names = await dns.reverse(ip).catch(() => []);
    return { target: host, ip, hostnames: names, ptr: names[0] || null };
  },
  subdomains: async host => {
    const domain = host.split('.').slice(-2).join('.');
    const data = await cached(`crt:${domain}`, () => fetchJson(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`));
    const names = new Set();
    for (const row of Array.isArray(data) ? data : []) {
      for (const name of String(row.name_value || '').split('\n')) {
        const value = name.trim().toLowerCase().replace(/^\*\./, '');
        if (value === domain || value.endsWith(`.${domain}`) && value.length <= 253) names.add(value);
      }
    }
    return { target: host, domain, source: 'crt.sh Certificate Transparency', count: names.size, subdomains: [...names].sort().slice(0, 500) };
  },
  whois: async host => {
    if (net.isIP(host)) return { target: host, note: 'IP WHOIS is available through the IP intelligence panel; this endpoint queries domain RDAP.' };
    const data = await cached(`rdap:${host}`, () => fetchJson(`https://rdap.org/domain/${encodeURIComponent(host)}`));
    const events = (data.events || []).map(e => ({ action: e.eventAction, date: e.eventDate }));
    const registrar = (data.entities || []).find(e => (e.roles || []).includes('registrar'));
    return { target: host, domain_name: data.ldhName || host, registrar: registrar?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3] || registrar?.handle || null, status: data.status || [], name_servers: (data.nameservers || []).map(n => n.ldhName), events, createdDate: events.find(e => e.action === 'registration')?.date, expiration_date: events.find(e => e.action === 'expiration')?.date, updatedDate: events.find(e => e.action === 'last changed')?.date, raw: undefined };
  },
  geoloc: async host => {
    const ip = net.isIP(host) ? host : (await resolvePublic(host)).address;
    const data = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (data.success === false) throw new Error(data.message || 'Geolocation lookup failed.');
    return { target: host, ip, country: data.country, country_code: data.country_code, region: data.region, city: data.city, latitude: data.latitude, longitude: data.longitude, connection: data.connection || null, timezone: data.timezone?.id || null, source: 'ipwho.is' };
  },
  vuln: async host => {
    const info = await cached(`web:${host}`, () => inspectWeb(host));
    return nvdVulnerabilities(host, info);
  },
};

function secureEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(json), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(json);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/health') return send(res, 200, { ok: true, service: 'samaritan-scanner', mode: 'passive', scans: Object.keys(routes) });
  if (req.method !== 'GET' || !url.pathname.startsWith('/scan/')) return send(res, 404, { error: 'Not found' });
  const suppliedKey = String(req.headers['x-scanner-key'] || '');
  if (!KEY_CONFIGURED || !suppliedKey || !secureEqual(suppliedKey, KEY)) return send(res, 401, { error: 'Unauthorized' });
  const type = url.pathname.slice('/scan/'.length);
  const handler = routes[type];
  if (!handler) return send(res, 404, { error: 'Unsupported scan type', available: Object.keys(routes) });
  try {
    const host = normalizeTarget(url.searchParams.get('target') || '');
    const result = await handler(host);
    return send(res, 200, result);
  } catch (error) {
    return send(res, 400, { error: error instanceof Error ? error.message : 'Scan failed.' });
  }
});

server.requestTimeout = REQUEST_TIMEOUT + 2_000;
server.headersTimeout = REQUEST_TIMEOUT + 3_000;
server.listen(PORT, HOST, () => console.log(`[SAMARITAN SCANNER] Passive RECON listening on ${HOST}:${PORT}`));
