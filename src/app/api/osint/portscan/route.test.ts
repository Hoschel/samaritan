import { afterEach, describe, expect, it, vi } from 'vitest';
import { GET } from './route';

const scan = (target: string, ip: string) =>
  GET(new Request(`http://localhost:3000/api/osint/portscan?target=${encodeURIComponent(target)}`, { headers: { 'x-real-ip': ip } }));
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

afterEach(() => vi.unstubAllGlobals());

describe('GET /api/osint/portscan', () => {
  it('uses the free InternetDB public index and returns normalised ports', async () => {
    const fetchMock = vi.fn(async () => json({ ports: [443, 22, 80, 22], cpes: ['cpe:/a:nginx:nginx'], hostnames: ['dns.google'], domains: ['google'], tags: ['cdn'], vulns: ['CVE-2024-0001'] }));
    vi.stubGlobal('fetch', fetchMock);
    const response = await scan('8.8.8.8', '203.0.113.1');
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toContain('internetdb.shodan.io/8.8.8.8');
    expect(body.source).toBe('internetdb');
    expect(body.ports.map((p: { port: number; transport: string; service?: string }) => `${p.port}/${p.transport}/${p.service}`)).toEqual(['22/tcp/ssh', '22/tcp/ssh', '80/tcp/http', '443/tcp/https']);
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

  it('refuses private targets before calling an upstream source', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const response = await scan('10.0.0.1', '203.0.113.4');
    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
