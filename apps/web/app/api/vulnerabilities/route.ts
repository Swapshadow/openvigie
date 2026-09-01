import { NextResponse } from 'next/server';
import type { Vulnerability, VulnerabilityResponse } from '../../vulnerability-types';

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_API = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CACHE_TTL = 15 * 60 * 1000;
const KEV_TTL = 60 * 60 * 1000;
const FORCE_COOLDOWN = 60 * 1000;

type CacheEntry = { createdAt: number; expiresAt: number; payload: VulnerabilityResponse };
type KevEntry = {
  cveID: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: string;
};

const responseCache = new Map<string, CacheEntry>();
let kevCache: { expiresAt: number; entries: Map<string, KevEntry> } | null = null;

async function proxyCollector(requestUrl: URL, method: 'GET' | 'DELETE') {
  const baseUrl = process.env.OPENVIGIE_COLLECTOR_URL?.replace(/\/$/, '');
  if (!baseUrl) return null;
  try {
    const response = await fetch(`${baseUrl}/vulnerabilities?${requestUrl.searchParams.toString()}`, {
      method,
      cache: 'no-store',
      signal: AbortSignal.timeout(35_000),
    });
    return new NextResponse(await response.arrayBuffer(), {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('Content-Type') ?? 'application/json' },
    });
  } catch {
    return null;
  }
}

function clean(value: string | null, max = 100) {
  return (value ?? '').trim().slice(0, max);
}

function cpeComponent(value: string) {
  return value
    .toLowerCase()
    .replace(/\\/g, '\\\\')
    .replace(/([!"#$%&'()+,/:;<=>?@[\]^`{|}~])/g, '\\$1')
    .replace(/\s+/g, '_');
}

async function fetchJson<T>(url: string, headers: HeadersInit = {}): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 18_000);
  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'OpenVigie/0.2 (+https://github.com/Swapshadow/openvigie)', ...headers },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json() as T;
  } finally {
    clearTimeout(timer);
  }
}

async function getKevCatalog() {
  if (kevCache && kevCache.expiresAt > Date.now()) return kevCache.entries;
  const data = await fetchJson<{ vulnerabilities?: KevEntry[] }>(CISA_KEV_API);
  const entries = new Map((data.vulnerabilities ?? []).map((entry) => [entry.cveID, entry]));
  kevCache = { expiresAt: Date.now() + KEV_TTL, entries };
  return entries;
}

type NvdMetric = {
  cvssData?: {
    baseScore?: number;
    baseSeverity?: string;
    vectorString?: string;
    attackVector?: string;
    privilegesRequired?: string;
    userInteraction?: string;
    confidentialityImpact?: string;
    integrityImpact?: string;
    availabilityImpact?: string;
  };
};

type NvdCve = {
  id: string;
  published: string;
  lastModified: string;
  descriptions?: Array<{ lang: string; value: string }>;
  weaknesses?: Array<{ description?: Array<{ lang: string; value: string }> }>;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  metrics?: {
    cvssMetricV40?: NvdMetric[];
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: NvdMetric[];
  };
};

type NvdResponse = {
  totalResults?: number;
  vulnerabilities?: Array<{ cve: NvdCve }>;
};

function metricFor(cve: NvdCve) {
  return cve.metrics?.cvssMetricV40?.[0]
    ?? cve.metrics?.cvssMetricV31?.[0]
    ?? cve.metrics?.cvssMetricV30?.[0]
    ?? cve.metrics?.cvssMetricV2?.[0]
    ?? null;
}

function normalizeCve(cve: NvdCve, kev: Map<string, KevEntry>): Vulnerability {
  const metric = metricFor(cve)?.cvssData;
  const kevEntry = kev.get(cve.id);
  const description = cve.descriptions?.find((item) => item.lang === 'fr')?.value
    ?? cve.descriptions?.find((item) => item.lang === 'en')?.value
    ?? 'Description non disponible.';

  return {
    id: cve.id,
    description,
    score: metric?.baseScore ?? null,
    severity: metric?.baseSeverity ?? 'UNKNOWN',
    vector: metric?.vectorString ?? null,
    attackVector: metric?.attackVector ?? null,
    privilegesRequired: metric?.privilegesRequired ?? null,
    userInteraction: metric?.userInteraction ?? null,
    confidentialityImpact: metric?.confidentialityImpact ?? null,
    integrityImpact: metric?.integrityImpact ?? null,
    availabilityImpact: metric?.availabilityImpact ?? null,
    weaknesses: (cve.weaknesses ?? [])
      .flatMap((weakness) => weakness.description ?? [])
      .filter((item) => item.lang === 'en')
      .map((item) => item.value)
      .filter((value, index, values) => values.indexOf(value) === index),
    published: cve.published,
    lastModified: cve.lastModified,
    references: (cve.references ?? []).slice(0, 20).map((reference) => ({
      url: reference.url,
      source: reference.source ?? new URL(reference.url).hostname,
      tags: reference.tags ?? [],
    })),
    kev: kevEntry ? {
      dateAdded: kevEntry.dateAdded,
      dueDate: kevEntry.dueDate,
      requiredAction: kevEntry.requiredAction,
      knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
    } : null,
  };
}

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const collectorResponse = await proxyCollector(requestUrl, 'GET');
  if (collectorResponse) return collectorResponse;
  const vendor = clean(requestUrl.searchParams.get('vendor'));
  const product = clean(requestUrl.searchParams.get('product'));
  const version = clean(requestUrl.searchParams.get('version'), 60);
  const requestedPart = clean(requestUrl.searchParams.get('part'), 1);
  const part = ['a', 'o', 'h'].includes(requestedPart) ? requestedPart : 'a';
  const cpeVendor = clean(requestUrl.searchParams.get('cpeVendor'));
  const cpeProduct = clean(requestUrl.searchParams.get('cpeProduct'));
  const force = requestUrl.searchParams.get('force') === '1';

  if (!vendor || !product) {
    return NextResponse.json({ error: 'Les paramètres vendor et product sont requis.' }, { status: 400 });
  }

  const cacheKey = [vendor, product, version, part, cpeVendor, cpeProduct].join('|').toLowerCase();
  const cached = responseCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() && (!force || cached.createdAt > Date.now() - FORCE_COOLDOWN)) {
    return NextResponse.json({ ...cached.payload, cached: true });
  }

  let method: 'cpe' | 'keyword' = cpeVendor && cpeProduct && version ? 'cpe' : 'keyword';
  const cpe = method === 'cpe'
    ? `cpe:2.3:${part}:${cpeComponent(cpeVendor)}:${cpeComponent(cpeProduct)}:${cpeComponent(version)}:*:*:*:*:*:*:*`
    : '';
  const keyword = [vendor, product, version].filter(Boolean).join(' ');
  const headers: HeadersInit = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const sourceStatus: VulnerabilityResponse['sources'] = [];

  try {
    let queryUrl = `${NVD_API}?resultsPerPage=50&${method === 'cpe' ? `cpeName=${encodeURIComponent(cpe)}` : `keywordSearch=${encodeURIComponent(keyword)}`}`;
    let nvd = await fetchJson<NvdResponse>(queryUrl, headers);

    if (method === 'cpe' && (nvd.totalResults ?? 0) === 0) {
      method = 'keyword';
      queryUrl = `${NVD_API}?resultsPerPage=50&keywordSearch=${encodeURIComponent(keyword)}`;
      nvd = await fetchJson<NvdResponse>(queryUrl, headers);
    }

    sourceStatus.push({
      name: 'NVD / NIST', status: 'online', url: 'https://nvd.nist.gov/',
      detail: method === 'cpe' ? 'Correspondance CPE et version exacte' : 'Recherche textuelle de repli à vérifier',
    });

    let kev = new Map<string, KevEntry>();
    try {
      kev = await getKevCatalog();
      sourceStatus.push({ name: 'CISA KEV', status: 'online', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', detail: 'Catalogue des vulnérabilités exploitées' });
    } catch {
      sourceStatus.push({ name: 'CISA KEV', status: 'degraded', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', detail: 'Source temporairement indisponible' });
    }

    const vulnerabilities = (nvd.vulnerabilities ?? [])
      .map(({ cve: item }) => normalizeCve(item, kev))
      .sort((a, b) => Number(Boolean(b.kev)) - Number(Boolean(a.kev)) || (b.score ?? 0) - (a.score ?? 0));

    const payload: VulnerabilityResponse = {
      asset: { vendor, product, version },
      matching: { method, confidence: method === 'cpe' ? 'high' : 'medium', query: method === 'cpe' ? cpe : keyword },
      vulnerabilities,
      totalResults: nvd.totalResults ?? vulnerabilities.length,
      fetchedAt: new Date().toISOString(),
      cached: false,
      sources: sourceStatus,
      relatedArticles: [],
    };

    responseCache.set(cacheKey, { createdAt: Date.now(), expiresAt: Date.now() + CACHE_TTL, payload });
    return NextResponse.json(payload, { headers: { 'Cache-Control': 'private, max-age=300' } });
  } catch (error) {
    const message = error instanceof Error && error.name === 'AbortError'
      ? 'La source NVD a dépassé le délai de réponse.'
      : 'La source NVD est temporairement indisponible ou a limité les requêtes.';
    return NextResponse.json({ error: message }, { status: 503 });
  }
}

export async function DELETE(request: Request) {
  const requestUrl = new URL(request.url);
  const collectorResponse = await proxyCollector(requestUrl, 'DELETE');
  if (collectorResponse) return collectorResponse;

  const cacheKey = [
    clean(requestUrl.searchParams.get('vendor')),
    clean(requestUrl.searchParams.get('product')),
    clean(requestUrl.searchParams.get('version'), 60),
    clean(requestUrl.searchParams.get('part'), 1) || 'a',
    clean(requestUrl.searchParams.get('cpeVendor')),
    clean(requestUrl.searchParams.get('cpeProduct')),
  ].join('|').toLowerCase();
  responseCache.delete(cacheKey);
  return NextResponse.json({ success: true });
}
