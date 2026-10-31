import { NextResponse } from 'next/server';
import { isIP } from 'node:net';
import { portServiceName } from '@/lib/osint-utils';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';

export const dynamic = 'force-dynamic';

export interface ScannedPort {
  port: number;
  transport: string;
  service?: string;
  cpes: string[];
  vulns: string[];
}

export interface PortScanResult {
  target: string;
  ip: string;
  source: 'internetdb';
  ports: ScannedPort[];
  hostnames: string[];
  domains: string[];
  tags: string[];
  cpes: string[];
  vulns: string[];
  note?: string;
}

const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.filter((item): item is string => typeof item === 'string')
  : [];

async function fromInternetDb(target: string, ip: string): Promise<PortScanResult> {
  const response = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
    signal: AbortSignal.timeout(8_000),
    cache: 'no-store',
    headers: { accept: 'application/json' },
  });
  const empty: PortScanResult = {
    target, ip, source: 'internetdb', ports: [], hostnames: [], domains: [], tags: [], cpes: [], vulns: [],
  };
  if (response.status === 404) return { ...empty, note: 'No record is currently available in the public InternetDB index. This is not an active scan.' };
  if (!response.ok) throw new Error(`Public InternetDB returned HTTP ${response.status}.`);

  const data: { ports?: unknown[]; hostnames?: unknown; domains?: unknown; tags?: unknown; cpes?: unknown; vulns?: unknown } = await response.json();
  const ports = [...new Set((Array.isArray(data.ports) ? data.ports : [])
    .filter((port): port is number => typeof port === 'number' && Number.isInteger(port) && port > 0 && port <= 65_535))]
    .sort((a, b) => a - b)
    .map(port => ({ port, transport: 'tcp', service: portServiceName(port), cpes: [], vulns: [] }));
  return {
    ...empty,
    ports,
    hostnames: strings(data.hostnames),
    domains: strings(data.domains),
    tags: strings(data.tags),
    cpes: strings(data.cpes),
    vulns: strings(data.vulns),
    note: 'Read-only lookup against the public InternetDB index. No packets were sent to the target by Samaritan.',
  };
}

export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get('target')?.trim() ?? '';
  if (!target) return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });

  if (isRateLimited(`portscan:${getClientIp(req)}`, 15, 60_000)) {
    return NextResponse.json({ error: 'Too many lookups — wait a minute and try again.' }, { status: 429 });
  }

  const validation = await validateHost(target);
  if (!validation.ok) return NextResponse.json({ error: `Cannot look up ${target}: ${validation.reason}` }, { status: 400 });
  const ip = validation.resolved?.find(address => isIP(address) === 4) ?? validation.resolved?.[0];
  if (!ip) return NextResponse.json({ error: `Cannot look up ${target}: no public address` }, { status: 400 });

  try {
    return NextResponse.json(await fromInternetDb(target, ip));
  } catch (error) {
    return NextResponse.json({ error: 'Public host-index lookup failed', detail: error instanceof Error ? error.message : 'Unknown error' }, { status: 502 });
  }
}
