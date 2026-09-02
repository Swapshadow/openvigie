import { NextResponse } from 'next/server';

const TIMEOUT_MS = 8_000;

const WATCH_SOURCES = [
  { id: 'cert-fr-alertes', collectorId: 'cert-fr-alertes', testUrl: 'https://cert.ssi.gouv.fr/alerte/feed/' },
  { id: 'anssi-actualites', collectorId: 'anssi-actualites', testUrl: 'https://cyber.gouv.fr/actualites/rss/' },
  { id: 'cisa-advisories', collectorId: 'cisa-advisories', testUrl: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
  { id: 'enisa', testUrl: 'https://www.enisa.europa.eu/news' },
  { id: 'nvd', testUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1' },
  { id: 'cisa-kev', testUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  { id: 'cve-program', testUrl: 'https://cveawg.mitre.org/api/cve/CVE-2024-3094' },
  { id: 'epss', testUrl: 'https://api.first.org/data/v1/epss?cve=CVE-2024-3094' },
  { id: 'cisco-psirt', collectorId: 'cisco-psirt', testUrl: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml' },
  { id: 'msrc', collectorId: 'msrc', testUrl: 'https://api.msrc.microsoft.com/update-guide/rss' },
  { id: 'fortinet-psirt', testUrl: 'https://www.fortiguard.com/psirt' },
  { id: 'palo-alto-psirt', collectorId: 'palo-alto-psirt', testUrl: 'https://security.paloaltonetworks.com/rss.xml' },
  { id: 'citizen-lab', collectorId: 'citizen-lab', testUrl: 'https://citizenlab.ca/feed/' },
  { id: 'amnesty-security-lab', collectorId: 'amnesty-security-lab', testUrl: 'https://securitylab.amnesty.org/latest/feed/' },
  { id: 'unit-42', collectorId: 'unit-42', testUrl: 'https://unit42.paloaltonetworks.com/feed/' },
] as const;

type CollectorStatus = {
  id: string;
  status: 'online' | 'degraded' | 'pending';
  lastSuccess: string | null;
  nextRefresh: string | null;
  error: string | null;
  watchFrequency: string | null;
  watchRefreshSeconds: number | null;
};

async function collectorStatuses() {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) return { available: false, statuses: new Map<string, CollectorStatus>() };
  try {
    const response = await fetch(`${collectorBase}/feeds/status`, { cache: 'no-store', signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return { available: false, statuses: new Map<string, CollectorStatus>() };
    const payload = await response.json() as { sources?: CollectorStatus[] };
    return { available: true, statuses: new Map((payload.sources ?? []).map((item) => [item.id, item])) };
  } catch {
    return { available: false, statuses: new Map<string, CollectorStatus>() };
  }
}

async function probe(source: typeof WATCH_SOURCES[number], collector: Map<string, CollectorStatus>) {
  const checkedAt = new Date().toISOString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(source.testUrl, {
      cache: 'no-store',
      redirect: 'follow',
      headers: {
        Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/html;q=0.8, */*;q=0.5',
        'User-Agent': 'OpenVigie/0.5 (+https://github.com/Swapshadow/openvigie)',
      },
      signal: controller.signal,
    });
    await response.body?.cancel();
    const collectorState = 'collectorId' in source ? collector.get(source.collectorId) : undefined;
    return {
      id: source.id,
      status: response.ok ? 'online' as const : 'degraded' as const,
      httpStatus: response.status,
      checkedAt,
      lastSuccess: response.ok ? checkedAt : collectorState?.lastSuccess ?? null,
      nextRefresh: collectorState?.nextRefresh ?? null,
      error: response.ok ? null : `La source a répondu HTTP ${response.status}.`,
      watchFrequency: collectorState?.watchFrequency ?? null,
      watchRefreshSeconds: collectorState?.watchRefreshSeconds ?? null,
    };
  } catch (error) {
    const collectorState = 'collectorId' in source ? collector.get(source.collectorId) : undefined;
    return {
      id: source.id,
      status: 'degraded' as const,
      httpStatus: null,
      checkedAt,
      lastSuccess: collectorState?.lastSuccess ?? null,
      nextRefresh: collectorState?.nextRefresh ?? null,
      error: error instanceof Error && error.name === 'AbortError' ? `Délai dépassé après ${TIMEOUT_MS / 1000} secondes.` : error instanceof Error ? error.message : 'Échec réseau non identifié.',
      watchFrequency: collectorState?.watchFrequency ?? null,
      watchRefreshSeconds: collectorState?.watchRefreshSeconds ?? null,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function GET() {
  const collector = await collectorStatuses();
  const sources = await Promise.all(WATCH_SOURCES.map((source) => probe(source, collector.statuses)));
  return NextResponse.json({
    checkedAt: new Date().toISOString(),
    collectorAvailable: collector.available,
    sources,
  }, { headers: { 'Cache-Control': 'no-store' } });
}

export async function POST(request: Request) {
  const collectorBase = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!collectorBase) return NextResponse.json({ error: 'Le collecteur Docker est indisponible.' }, { status: 503 });
  try {
    const payload = await request.json() as { sources?: Array<{ sourceId?: string; frequency?: string }> };
    if (!Array.isArray(payload.sources) || payload.sources.length > 50) {
      return NextResponse.json({ error: 'Planning de collecte invalide.' }, { status: 400 });
    }
    const sources = payload.sources.map((item) => ({
      sourceId: String(item.sourceId ?? '').slice(0, 80),
      frequency: String(item.frequency ?? '').slice(0, 30),
    }));
    const response = await fetch(`${collectorBase}/watch-plan`, {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sources }),
      signal: AbortSignal.timeout(8_000),
    });
    return new NextResponse(await response.arrayBuffer(), {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
    });
  } catch {
    return NextResponse.json({ error: 'Le planning n’a pas pu être transmis au collecteur.' }, { status: 503 });
  }
}
