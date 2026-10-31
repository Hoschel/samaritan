import { NextResponse } from 'next/server';
import { isIP } from 'node:net';
import { portServiceName } from '@/lib/osint-utils';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';

export const dynamic = 'force-dynamic';

export interface ScannedPort {
  port: number;
  transport: string;
  service?: string;
  product?: string;
  version?: string;
  banner?: string;
  title?: string;
  cpes: string[];
  vulns: string[];
  last_seen?: string;
}

export interface PortScanResult {
  target: string;
  ip: string;
  source: 'shodan' | 'internetdb';
  ports: ScannedPort[];
  hostnames: string[];
  domains: string[];
  tags: string[];
  cpes: string[];
  vulns: string[];
  org?: string;
  isp?: string;
  asn?: string;
  os?: string;
  location?: { city?: string; country?: string; lat?: number; lng?: number };
  last_update?: string;
  note?: string;
}

interface ShodanService {
  port?: number;
  transport?: string;
  product?: string;
  version?: string;
  data?: string;
  timestamp?: string;
  cpe?: unknown;
  cpe23?: unknown;
  vulns?: unknown;
  _shodan?: { module?: string };
  http?: { title?: string };
  ssl?: { cert?: { subject?: { CN?: string } } };
}
interface ShodanHost {
  data?: ShodanService[];
  ports?: unknown[];
  hostnames?: unknown;
  domains?: unknown;
  tags?: unknown;
  vulns?: unknown;
  org?: string;
  isp?: string;
  asn?: string;
  os?: string | null;
  city?: string | null;
  country_name?: string;
  latitude?: number;
  longitude?: number;
  last_update?: string;
}

const BANNER_MAX = 600;
const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item): item is string => typeof item === 'string')
  : [];
const stringValues = (value: unknown): string[] => typeof value === 'string' ? [value] : strings(value);
const uniq = (items: string[]) => [...new Set(items)];
const vulnIds = (value: unknown): string[] => Array.isArray(value)
  ? strings(value)
  : value && typeof value === 'object'
    ? Object.keys(value as Record<string, unknown>)
    : [];

function emptyResult(target: string, ip: string, source: PortScanResult['source']): PortScanResult {
  return { target, ip, source, ports: [], hostnames: [], domains: [], tags: [], cpes: [], vulns: [] };
}

/** Read-only Shodan host-index request. It does not send probes to the target. */
async function shodanHost(ip: string, key: string): Promise<{ status: number; data?: ShodanHost }> {
  const url = new URL('https://api.shodan.io/shodan/host/' + encodeURIComponent(ip));
  url.searchParams.set('key', key);
  const response = await fetch(url, {
    signal: AbortSignal.timeout(12_000),
    cache: 'no-store',
    headers: { accept: 'application/json' },
  });
  if (!response.ok) return { status: response.status };
  return { status: response.status, data: await response.json() as ShodanHost };
}

function fromShodan(target: string, ip: string, host: ShodanHost): PortScanResult {
  const byKey = new Map<string, ScannedPort>();
  for (const service of Array.isArray(host.data) ? host.data : []) {
    if (!Number.isInteger(service?.port) || (service.port as number) < 1 || (service.port as number) > 65_535) continue;
    const port = service.port as number;
    const transport = typeof service.transport === 'string' ? service.transport : 'tcp';
    const key = port + '/' + transport;
    if (byKey.has(key)) continue;
    const banner = typeof service.data === 'string' ? service.data.trim() : '';
    byKey.set(key, {
      port, transport,
      service: service._shodan?.module || portServiceName(port),
      product: service.product,
      version: service.version,
      banner: banner ? banner.slice(0, BANNER_MAX) : undefined,
      title: service.http?.title || service.ssl?.cert?.subject?.CN,
      cpes: uniq([...stringValues(service.cpe23), ...stringValues(service.cpe)]),
      vulns: vulnIds(service.vulns),
      last_seen: service.timestamp,
    });
  }
  // Shodan can list a port without a corresponding service banner.
  for (const value of Array.isArray(host.ports) ? host.ports : []) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65_535) continue;
    if (![...byKey.values()].some(port => port.port === value)) {
      byKey.set(value + '/tcp', { port: value, transport: 'tcp', service: portServiceName(value), cpes: [], vulns: [] });
    }
  }
  const ports = [...byKey.values()].sort((a, b) => a.port - b.port || a.transport.localeCompare(b.transport));
  return {
    target, ip, source: 'shodan', ports,
    hostnames: strings(host.hostnames),
    domains: strings(host.domains),
    tags: strings(host.tags),
    cpes: uniq(ports.flatMap(port => port.cpes)),
    vulns: uniq([...vulnIds(host.vulns), ...ports.flatMap(port => port.vulns)]),
    org: host.org || undefined,
    isp: host.isp || undefined,
    asn: host.asn || undefined,
    os: host.os || undefined,
    location: {
      city: host.city || undefined,
      country: host.country_name || undefined,
      lat: typeof host.latitude === 'number' ? host.latitude : undefined,
      lng: typeof host.longitude === 'number' ? host.longitude : undefined,
    },
    last_update: host.last_update,
    note: 'Passive Shodan host-index result. Samaritan did not send packets to the target.',
  };
}

/** Free keyless fallback: open ports, CPEs and CVEs without service banners. */
async function fromInternetDb(target: string, ip: string, note?: string): Promise<PortScanResult> {
  const response = await fetch('https://internetdb.shodan.io/' + encodeURIComponent(ip), {
    signal: AbortSignal.timeout(8_000), cache: 'no-store', headers: { accept: 'application/json' },
  });
  const empty = emptyResult(target, ip, 'internetdb');
  if (response.status === 404) {
    return { ...empty, note: note ?? 'No record is currently available in the public InternetDB index. This is not an active scan.' };
  }
  if (!response.ok) throw new Error('Public InternetDB returned HTTP ' + response.status + '.');
  const data: { ports?: unknown[]; hostnames?: unknown; domains?: unknown; tags?: unknown; cpes?: unknown; vulns?: unknown } = await response.json();
  const ports = [...new Set((Array.isArray(data.ports) ? data.ports : [])
    .filter((port): port is number => typeof port === 'number' && Number.isInteger(port) && port > 0 && port <= 65_535))]
    .sort((a, b) => a - b)
    .map(port => ({ port, transport: 'tcp', service: portServiceName(port), cpes: [], vulns: [] }));
  return {
    ...empty, ports,
    hostnames: strings(data.hostnames), domains: strings(data.domains), tags: strings(data.tags),
    cpes: strings(data.cpes), vulns: strings(data.vulns),
    note: note ?? 'Read-only lookup against the public InternetDB index. No packets were sent to the target by Samaritan.',
  };
}

export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get('target')?.trim() ?? '';
  if (!target) return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });
  if (isRateLimited('portscan:' + getClientIp(req), 15, 60_000)) {
    return NextResponse.json({ error: 'Too many lookups — wait a minute and try again.' }, { status: 429 });
  }
  // Resolve and reject private/reserved targets before contacting any upstream.
  const validation = await validateHost(target);
  if (!validation.ok) return NextResponse.json({ error: 'Cannot look up ' + target + ': ' + validation.reason }, { status: 400 });
  const ip = validation.resolved?.find(address => isIP(address) === 4) ?? validation.resolved?.[0];
  if (!ip) return NextResponse.json({ error: 'Cannot look up ' + target + ': no public address' }, { status: 400 });

  try {
    const key = process.env.SHODAN_API_KEY?.trim();
    if (!key) return NextResponse.json(await fromInternetDb(target, ip));
    try {
      const host = await shodanHost(ip, key);
      if (host.data) return NextResponse.json(fromShodan(target, ip, host.data));
      if (host.status === 404) {
        return NextResponse.json({ ...emptyResult(target, ip, 'shodan'), note: 'Shodan has no indexed record for this host. This is not an active scan.' } satisfies PortScanResult);
      }
      const why = host.status === 401 || host.status === 403 ? 'the Shodan API key was refused'
        : host.status === 429 ? 'Shodan rate-limited the key' : 'Shodan returned HTTP ' + host.status;
      return NextResponse.json(await fromInternetDb(target, ip, 'Showing the free InternetDB fallback because ' + why + '.'));
    } catch {
      // The paid/keyed source is an enhancement, never a reason to lose the free fallback.
      return NextResponse.json(await fromInternetDb(target, ip, 'Showing the free InternetDB fallback because the Shodan API was unavailable.'));
    }
  } catch (error) {
    return NextResponse.json({ error: 'Public host-intelligence lookup failed', detail: error instanceof Error ? error.message : 'Unknown error' }, { status: 502 });
  }
}
