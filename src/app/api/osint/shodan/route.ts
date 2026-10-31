import { NextResponse } from 'next/server';
import { isIP } from 'node:net';
import { getClientIp, isRateLimited, validateHost } from '@/lib/ssrf-guard';

export const dynamic = 'force-dynamic';

/**
 * Compatibility route for the former Shodan panel. It now performs a read-only
 * lookup against the public, keyless InternetDB index; it never invokes the
 * paid Shodan API and never probes the target.
 */
export async function GET(req: Request) {
  const ip = new URL(req.url).searchParams.get('ip')?.trim() || '';
  if (!ip) return NextResponse.json({ error: 'Missing IP parameter' }, { status: 400 });
  if (isRateLimited(`internetdb:${getClientIp(req)}`, 12, 60_000)) {
    return NextResponse.json({ error: 'Too many public host-index lookups. Try again in a minute.' }, { status: 429 });
  }
  if (isIP(ip) === 0) return NextResponse.json({ error: 'Enter a public IPv4 or IPv6 address.' }, { status: 400 });

  const validation = await validateHost(ip);
  if (!validation.ok) return NextResponse.json({ error: `Lookup blocked: ${validation.reason}` }, { status: 400 });
  const publicIp = validation.resolved?.find(address => isIP(address) !== 0);
  if (!publicIp) return NextResponse.json({ error: 'No public address was resolved.' }, { status: 400 });

  try {
    const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(publicIp)}`, {
      signal: AbortSignal.timeout(8_000), cache: 'no-store', headers: { accept: 'application/json' },
    });
    if (res.status === 404) return NextResponse.json({
      ip: publicIp, status: 'No public InternetDB records found', ports: [], cpes: [], hostnames: [], tags: [], vulns: [],
      note: 'No indexed record was found. Samaritan did not send packets to the target.',
    });
    if (!res.ok) throw new Error(`InternetDB returned HTTP ${res.status}`);
    return NextResponse.json(await res.json(), { headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    return NextResponse.json({ error: 'Public host-index lookup failed', detail: error instanceof Error ? error.message : 'Unknown error' }, { status: 502 });
  }
}
