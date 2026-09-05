'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { findProduct, findVendor } from './asset-catalog';
import type { InventoryAsset } from './vulnerability-types';

const INVENTORY_KEY = 'openvigie.inventory.v1';

type CertEntry = {
  id: string;
  title: string;
  url: string;
  excerpt: string;
  publishedAt: string | null;
  kind: 'alerte' | 'avis';
  subject: string | null;
  cves: string[];
  kevCves: string[];
  source: { id: string; name: string; homepage: string };
};

type CertDigest = {
  generatedAt: string;
  period: { label: string; start: string; end: string };
  stats: { alertes: number; avis: number; cves: number; kev: number };
  alertes: CertEntry[];
  avis: CertEntry[];
  subjects: Array<{ subject: string; count: number }>;
  source: { name: string; homepage: string; notice: string };
};

const WINDOWS: Array<[string, string]> = [
  ['7', '7 jours'],
  ['30', '30 jours'],
  ['90', '3 mois'],
];

function formatDate(value: string | null) {
  if (!value) return 'Date non fournie';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date non fournie';
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'long' }).format(date);
}

function readInventory(): InventoryAsset[] {
  try {
    const raw = window.localStorage.getItem(INVENTORY_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as InventoryAsset[]) : [];
  } catch {
    return [];
  }
}

type MatchedAsset = { asset: InventoryAsset; name: string };

/** Words present in product names that identify no product.
 *
 * "Stormshield Network Security" must match on "stormshield" alone; matching on
 * "security" would tag every advisory as concerning the asset. */
const GENERIC_TERMS = new Set([
  'server', 'servers', 'desktop', 'linux', 'unix', 'windows',
  'network', 'networks', 'networking', 'system', 'systems', 'software',
  'secure', 'security', 'manager', 'management', 'agent', 'client',
  'cloud', 'service', 'services', 'enterprise', 'platform', 'edition',
  'appliance', 'appliances', 'suite', 'center', 'centre', 'console',
  'protection', 'solution', 'solutions', 'professional', 'standard',
  'advanced', 'premium', 'core', 'base', 'open', 'source', 'project',
]);

/** Does this CERT-FR entry name something the user actually runs?
 *
 * Matching stays deliberately conservative — the catalog vendor name, or a
 * significant word of the product name, appearing in the headline — because a
 * false "concerne ton parc" badge is worse than no badge at all. */
function matchesInventory(entry: CertEntry, assets: InventoryAsset[]): MatchedAsset[] {
  if (!assets.length) return [];
  const haystack = `${entry.title} ${entry.subject ?? ''}`.toLowerCase();
  const matched: MatchedAsset[] = [];
  for (const asset of assets) {
    const vendor = findVendor(asset.vendorId);
    const product = findProduct(asset.vendorId, asset.productId);
    // Product names carry slashes and qualifiers ("FortiOS / FortiGate"); keep
    // tokens of four characters or more, minus the ones that name no product.
    const tokens = product.name.toLowerCase()
      .split(/[^a-z0-9.+]+/)
      .filter((token) => token.length >= 4 && !GENERIC_TERMS.has(token));
    const hit = haystack.includes(vendor.name.toLowerCase()) || tokens.some((token) => haystack.includes(token));
    if (hit) matched.push({ asset, name: asset.label || `${vendor.name} ${product.name}` });
  }
  return matched;
}

function EntryCard({ entry, matched }: { entry: CertEntry; matched: MatchedAsset[] }) {
  const isAlert = entry.kind === 'alerte';
  return (
    <li className={`cert-entry${isAlert ? ' is-alert' : ''}${matched.length ? ' is-matched' : ''}`}>
      <div className="cert-entry-head">
        <span className={`cert-kind${isAlert ? ' alert' : ''}`}>{isAlert ? 'Alerte' : 'Avis'}</span>
        {entry.kevCves.length > 0 ? <span className="cert-kev">Exploitation connue</span> : null}
        {matched.length > 0 ? (
          <span className="cert-match">Concerne ton parc · {matched.length}</span>
        ) : null}
        <time dateTime={entry.publishedAt ?? undefined}>{formatDate(entry.publishedAt)}</time>
      </div>
      <h3>
        <a href={entry.url} target="_blank" rel="noreferrer noopener">{entry.title}</a>
      </h3>
      {entry.subject ? <p className="cert-subject">{entry.subject}</p> : null}
      {entry.excerpt ? <p className="cert-excerpt">{entry.excerpt}</p> : null}
      {matched.length > 0 ? (
        <p className="cert-matched-assets">
          {matched.slice(0, 4).map(({ asset, name }) => <span key={asset.id}>{name}</span>)}
        </p>
      ) : null}
      {entry.cves.length > 0 ? (
        <ul className="cert-cves">
          {entry.cves.slice(0, 10).map((cve) => (
            <li key={cve} className={entry.kevCves.includes(cve) ? 'kev' : undefined}>{cve}</li>
          ))}
          {entry.cves.length > 10 ? <li className="more">+{entry.cves.length - 10}</li> : null}
        </ul>
      ) : null}
    </li>
  );
}

export default function CertFrPanel() {
  const [days, setDays] = useState('30');
  const [data, setData] = useState<CertDigest | null>(null);
  const [assets, setAssets] = useState<InventoryAsset[]>([]);
  const [onlyMine, setOnlyMine] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    const requestId = ++requestSequence.current;
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/bulletin-certfr?days=${days}`, { cache: 'no-store', signal });
      const payload = await response.json() as CertDigest & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Le fil CERT-FR est indisponible.');
      if (requestId !== requestSequence.current) return;
      setData(payload);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (requestId !== requestSequence.current) return;
      setError(caught instanceof Error ? caught.message : 'Le fil CERT-FR est indisponible.');
    } finally {
      if (!signal?.aborted && requestId === requestSequence.current) setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setAssets(readInventory());
      void load(controller.signal);
    }, 0);
    return () => {
      requestSequence.current += 1;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [load]);

  const decorated = useMemo(() => {
    const decorate = (entries: CertEntry[]) =>
      entries.map((entry) => ({ entry, matched: matchesInventory(entry, assets) }));
    return { alertes: decorate(data?.alertes ?? []), avis: decorate(data?.avis ?? []) };
  }, [data, assets]);

  const matchedCount = decorated.alertes.filter((item) => item.matched.length).length
    + decorated.avis.filter((item) => item.matched.length).length;

  const alertes = onlyMine ? decorated.alertes.filter((item) => item.matched.length) : decorated.alertes;
  const avis = onlyMine ? decorated.avis.filter((item) => item.matched.length) : decorated.avis;

  return (
    <div className="cert-panel">
      <header className="cert-masthead">
        <div>
          <p className="eyebrow">Autorité nationale · ANSSI</p>
          <h2>CERT-FR</h2>
          <p className="cert-sub">
            {data
              ? `${data.period.label} · ${data.stats.alertes} alerte${data.stats.alertes > 1 ? 's' : ''} · ${data.stats.avis} avis`
              : 'Chargement des avis officiels…'}
          </p>
        </div>
        <div className="cert-controls">
          <div className="cert-window" role="tablist" aria-label="Fenêtre CERT-FR">
            {WINDOWS.map(([id, label]) => (
              <button type="button" role="tab" key={id} aria-selected={days === id} onClick={() => setDays(id)}>
                {label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="cert-filter-mine"
            aria-pressed={onlyMine}
            onClick={() => setOnlyMine((value) => !value)}
            disabled={!assets.length}
            title={assets.length ? undefined : 'Déclare des équipements dans « Mon parc » pour activer ce filtre'}
          >
            Mon parc {matchedCount > 0 ? <i>{matchedCount}</i> : null}
          </button>
        </div>
      </header>

      {data ? (
        <div className="cert-kpis">
          <div><span>{data.stats.alertes}</span><small>Alertes</small></div>
          <div><span>{data.stats.avis}</span><small>Avis</small></div>
          <div><span>{data.stats.cves}</span><small>CVE citées</small></div>
          <div className={data.stats.kev ? 'hot' : undefined}><span>{data.stats.kev}</span><small>Exploitation connue</small></div>
          <div className={matchedCount ? 'hot' : undefined}><span>{matchedCount}</span><small>Sur ton parc</small></div>
        </div>
      ) : null}

      {error ? (
        <div className="cert-message cert-error">
          <strong>Fil CERT-FR indisponible</strong>
          <p>{error}</p>
          <button type="button" onClick={() => void load()}>Réessayer</button>
        </div>
      ) : loading && !data ? (
        <div className="cert-message"><i />
          <div><strong>Lecture des avis CERT-FR</strong><p>Alertes et avis officiels de l’ANSSI.</p></div>
        </div>
      ) : (
        <>
          {onlyMine && !alertes.length && !avis.length ? (
            <div className="cert-message">
              <div>
                <strong>Aucun avis ne cite ton parc</strong>
                <p>Sur cette fenêtre, aucun avis CERT-FR ne nomme un équipement déclaré. Élargis la période ou retire le filtre.</p>
              </div>
            </div>
          ) : null}

          {alertes.length > 0 ? (
            <section className="cert-section">
              <h3 className="cert-section-title alert">
                Alertes de sécurité <i>{alertes.length}</i>
              </h3>
              <p className="cert-section-note">Exploitation en cours ou menace nationale immédiate. À traiter en priorité.</p>
              <ul className="cert-list">
                {alertes.map(({ entry, matched }) => <EntryCard key={entry.id} entry={entry} matched={matched} />)}
              </ul>
            </section>
          ) : null}

          {avis.length > 0 ? (
            <section className="cert-section">
              <h3 className="cert-section-title">
                Avis de sécurité <i>{avis.length}</i>
              </h3>
              <p className="cert-section-note">Vulnérabilités publiées avec correctifs disponibles ou contournements.</p>
              <ul className="cert-list">
                {avis.map(({ entry, matched }) => <EntryCard key={entry.id} entry={entry} matched={matched} />)}
              </ul>
            </section>
          ) : null}

          {data && data.subjects.length > 0 ? (
            <section className="cert-subjects">
              <h3>Produits les plus cités</h3>
              <ul>
                {data.subjects.map((item) => (
                  <li key={item.subject}>{item.subject}<i>{item.count}</i></li>
                ))}
              </ul>
            </section>
          ) : null}
        </>
      )}

      {data ? (
        <footer className="cert-footer">
          <p><strong>{data.source.name}</strong> · <a href={data.source.homepage} target="_blank" rel="noreferrer noopener">cert.ssi.gouv.fr ↗</a></p>
          <p>{data.source.notice}</p>
        </footer>
      ) : null}
    </div>
  );
}
