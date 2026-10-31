import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GET } from './route';

const scan = (target: string, ip: string) =>
  GET(new Request(`http://localhost:3000/api/osint/portscan?target=${encodeURIComponent(target)}`, { headers: { 'x-real-ip': ip } }));
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

beforeEach(() => vi.stubEnv('SHODAN_API_KEY', ''));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('GET /api/osint/portscan', () => {
  it('uses the free InternetDB public index and returns normalised ports', async () => {
    const fetchMock = vi.fn(async () => json({ ports: [443, 22, 80, 22], cpes: ['cpe:/a:nginx:nginx'], hostnames: ['dns.google'], domains: ['google'], tags: ['cdn'], vulns: ['CVE-2024-0001'] }));
    vi.stubGlobal('fetch', fetchMock);
    const response = await scan('8.8.8.8', '203.0.113.1');
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toContain('internetdb.shodan.io/8.8.8.8');
    expect(body.source).toBe('internetdb');
    expect(body.ports.map((p: { port: number; transport: string; service?: string }) => `${p.port}/${p.transport}/${p.service}`)).toEqual(['22/tcp/ssh', '80/tcp/http', '443/tcp/https']);
    expect(body.vulns).toEqual(['CVE-2024-0001']);
    expect(body.note).toMatch(/No packets were sent/);
  });

  it('returns an empty result when InternetDB has no record', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'not found' }, 404)));
    const body = await (await scan('1.1.1.1', '203.0.113.2')).json();
    expect(body.source).toBe('internetdb');
    expect(body.ports).toEqual([]);
    expect(body.note).toMatch(/not an active scan/i);
  });

  it('uses the full passive Shodan host record when an API key is configured', async () => {
    vi.stubEnv('SHODAN_API_KEY', 'test-shodan-key');
    const fetchMock = vi.fn(async () => json({
      org: 'Example Networks', isp: 'Example ISP', asn: 'AS64500',
      city: 'Example City', country_name: 'Example Country', latitude: 12.3, longitude: 45.6,
      last_update: '2026-10-30T12:00:00.000000',
      ports: [443, 8443], hostnames: ['example.test'], domains: ['example.test'], tags: ['cloud'],
      vulns: ['CVE-2025-1234'],
      data: [{
        port: 443, transport: 'tcp', product: 'nginx', version: '1.27.0',
        data: 'HTTP/1.1 200 OK\\nServer: nginx', timestamp: '2026-10-30T12:00:00.000000',
        cpe: ['cpe:/a:nginx:nginx:1.27.0'], vulns: { 'CVE-2025-1234': { cvss: 8.1 } },
        http: { title: 'Example' }, _shodan: { module: 'https' },
      }],
    }));
    vi.stubGlobal('fetch', fetchMock);
    const body = await (await scan('8.8.4.4', '203.0.113.8')).json();
    expect(body.source).toBe('shodan');
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toContain('/shodan/host/8.8.4.4?key=test-shodan-key');
    expect(body.ports[0]).toMatchObject({ port: 443, product: 'nginx', version: '1.27.0', title: 'Example' });
    expect(body.org).toBe('Example Networks');
    expect(body.vulns).toContain('CVE-2025-1234');
    expect(body.note).toMatch(/Passive Shodan/);
  });

  it('falls back to InternetDB when the optional Shodan key is refused', async () => {
    vi.stubEnv('SHODAN_API_KEY', 'bad-shodan-key');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ error: 'unauthorized' }, 401))
      .mockResolvedValueOnce(json({ ports: [443], hostnames: ['example.test'] }));
    vi.stubGlobal('fetch', fetchMock);
    const body = await (await scan('1.0.0.1', '203.0.113.9')).json();
    expect(body.source).toBe('internetdb');
    expect(body.ports.map((p: { port: number }) => p.port)).toEqual([443]);
    expect(body.note).toMatch(/Shodan API key was refused/);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('refuses private targets before calling an upstream source', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const response = await scan('10.0.0.1', '203.0.113.4');
    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
