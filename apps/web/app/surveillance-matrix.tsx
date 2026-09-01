'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { findProduct, findVendor } from './asset-catalog';
import type { InventoryAsset, Vulnerability, VulnerabilityResponse } from './vulnerability-types';
import WatchPlan from './watch-plan';

const INVENTORY_KEY = 'openvigie.inventory.v1';
const RESOLVED_KEY = 'openvigie.matrix.resolved.v1';

type MatrixEntry = {
  key: string;
  asset: InventoryAsset;
  vendorName: string;
  productName: string;
  advisoryUrl: string;
  vulnerability: Vulnerability;
  priority: number;
  unavailable?: boolean;
};

type MatrixFilter = 'urgent' | 'all' | 'resolved';

function priorityFor(vulnerability: Vulnerability, asset: InventoryAsset) {
  const exposureBonus = asset.exposure === 'Exposé sur Internet' ? 18 : asset.exposure === 'Postes utilisateurs' ? 8 : 0;
  const kevBonus = vulnerability.kev ? 35 : 0;
  const criticalBonus = vulnerability.severity === 'CRITICAL' ? 15 : vulnerability.severity === 'HIGH' ? 6 : 0;
  const score = (vulnerability.score ?? 0) * 5;
  return Math.round(Math.min(100, score + kevBonus + criticalBonus + exposureBonus));
}

function urgency(entry: MatrixEntry) {
  if (entry.vulnerability.kev || entry.priority >= 85) return { label: 'Immédiat', level: 'critical' };
  if (entry.priority >= 65) return { label: 'Prioritaire', level: 'high' };
  return { label: 'À planifier', level: 'medium' };
}

function shortDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(date);
}

async function loadAsset(asset: InventoryAsset): Promise<MatrixEntry[]> {
  const vendor = findVendor(asset.vendorId);
  const product = findProduct(asset.vendorId, asset.productId);
  const parameters = new URLSearchParams({
    vendor: vendor.name,
    product: product.name,
    version: asset.version,
    part: product.part,
  });
  if (product.cpeVendor) parameters.set('cpeVendor', product.cpeVendor);
  if (product.cpeProduct) parameters.set('cpeProduct', product.cpeProduct);
  const response = await fetch(`/api/vulnerabilities?${parameters}`, { cache: 'no-store' });
  const payload = await response.json() as VulnerabilityResponse & { error?: string };
  if (!response.ok) throw new Error(payload.error ?? `Échec de la veille pour ${asset.label}`);
  return payload.vulnerabilities.map((vulnerability) => ({
      key: `${asset.id}:${vulnerability.id}`,
      asset,
      vendorName: vendor.name,
      productName: product.name,
      advisoryUrl: product.advisoryUrl,
      vulnerability,
      priority: priorityFor(vulnerability, asset),
    }));
}

function RiskMatrix() {
  const [inventory, setInventory] = useState<InventoryAsset[]>([]);
  const [entries, setEntries] = useState<MatrixEntry[]>([]);
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<MatrixFilter>('urgent');
  const [loading, setLoading] = useState(true);
  const [progress, setProgress] = useState(0);
  const [errors, setErrors] = useState(0);

  const refresh = useCallback(async (assets: InventoryAsset[]) => {
    setLoading(true);
    setProgress(0);
    setErrors(0);
    const collected: MatrixEntry[] = [];
    let next = 0;
    let failed = 0;
    const worker = async () => {
      while (next < assets.length) {
        const index = next++;
        try { collected.push(...await loadAsset(assets[index])); }
        catch { failed += 1; }
        setProgress(index + 1);
      }
    };
    await Promise.all(Array.from({ length: Math.min(3, assets.length) }, () => worker()));
    const representedAssets = new Set(collected.map((entry) => entry.asset.id));
    for (const asset of assets.filter((item) => !representedAssets.has(item.id))) {
      const vendor = findVendor(asset.vendorId);
      const product = findProduct(asset.vendorId, asset.productId);
      collected.push({
        key: `${asset.id}:unavailable`, asset, vendorName: vendor.name, productName: product.name,
        advisoryUrl: product.advisoryUrl, priority: 0, unavailable: true,
        vulnerability: { id: 'AUCUNE-CVE', description: 'Aucune vulnérabilité prioritaire corrélée pour cet équipement, ou sa source doit être resynchronisée.', score: null, severity: 'SURVEILLÉ', vector: null, attackVector: null, privilegesRequired: null, userInteraction: null, confidentialityImpact: null, integrityImpact: null, availabilityImpact: null, weaknesses: [], published: '', lastModified: '', references: [], kev: null },
      });
    }
    collected.sort((a, b) => b.priority - a.priority || Number(Boolean(b.vulnerability.kev)) - Number(Boolean(a.vulnerability.kev)) || (b.vulnerability.score ?? 0) - (a.vulnerability.score ?? 0));
    setEntries(collected);
    setErrors(failed);
    setLoading(false);
  }, []);

  useEffect(() => {
    let assets: InventoryAsset[] = [];
    let storedResolved: string[] = [];
    let active = true;
    try {
      const parsed = JSON.parse(localStorage.getItem(INVENTORY_KEY) ?? '[]') as InventoryAsset[];
      assets = Array.isArray(parsed) ? parsed : [];
      storedResolved = JSON.parse(localStorage.getItem(RESOLVED_KEY) ?? '[]') as string[];
    } catch { assets = []; }
    queueMicrotask(() => {
      if (!active) return;
      setResolved(new Set(storedResolved));
      setInventory(assets);
      if (assets.length) void refresh(assets); else setLoading(false);
    });
    return () => { active = false; };
  }, [refresh]);

  const visible = useMemo(() => inventory.map((asset) => {
    const assetEntries = entries.filter((entry) => entry.asset.id === asset.id);
    if (filter === 'resolved') return assetEntries.find((entry) => resolved.has(entry.key));
    if (filter === 'all') return assetEntries[0];
    return assetEntries.find((entry) => !resolved.has(entry.key));
  }).filter((entry): entry is MatrixEntry => Boolean(entry)), [entries, filter, inventory, resolved]);

  const currentByAsset = useMemo(() => inventory.map((asset) => entries.find((entry) => entry.asset.id === asset.id && !resolved.has(entry.key))).filter((entry): entry is MatrixEntry => Boolean(entry)), [entries, inventory, resolved]);
  const immediate = currentByAsset.filter((entry) => urgency(entry).level === 'critical').length;
  const high = currentByAsset.filter((entry) => urgency(entry).level === 'high').length;
  const affectedAssets = currentByAsset.filter((entry) => !entry.unavailable).length;

  const toggleResolved = (key: string) => {
    setResolved((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key); else next.add(key);
      localStorage.setItem(RESOLVED_KEY, JSON.stringify([...next]));
      return next;
    });
  };

  return (
    <section className="content matrix-workspace" id="main-content">
      <header className="matrix-hero glass-panel">
        <div><p className="eyebrow neon">Priorisation des correctifs</p><h1>Matrice de veille</h1><p>Les vulnérabilités les plus dangereuses sont rapprochées automatiquement des équipements et versions déclarés dans votre parc.</p></div>
        <button type="button" onClick={() => void refresh(inventory)} disabled={loading || !inventory.length}>{loading ? `Analyse ${progress}/${inventory.length}` : 'Actualiser la matrice'}</button>
      </header>

      {!inventory.length ? <section className="matrix-empty glass-panel"><span>⌁</span><h2>Aucun équipement à analyser</h2><p>Ajoutez d’abord vos systèmes dans « Mon parc ». La matrice se remplira automatiquement à partir de leurs versions.</p></section> : <>
        <section className="matrix-stats" aria-label="Synthèse des priorités">
          <article data-level="critical"><span>Action immédiate</span><strong>{immediate}</strong><p>CVE exploitées ou priorité maximale</p></article>
          <article data-level="high"><span>Prioritaires</span><strong>{high}</strong><p>À intégrer au prochain cycle court</p></article>
          <article><span>Équipements exposés</span><strong>{affectedAssets}</strong><p>Sur {inventory.length} élément{inventory.length > 1 ? 's' : ''} du parc</p></article>
          <article><span>CVE analysées</span><strong>{entries.filter((entry) => !entry.unavailable).length}</strong><p>{errors ? `${errors} équipement(s) à resynchroniser` : 'Une priorité affichée par équipement'}</p></article>
        </section>

        <section className="matrix-panel glass-panel">
          <header><div><span>PLAN DE REMÉDIATION</span><h2>Une priorité par équipement</h2></div><nav aria-label="Filtrer la matrice">{([['urgent', 'À traiter'], ['all', 'Priorité maximale'], ['resolved', 'Traitées']] as const).map(([id, label]) => <button type="button" aria-pressed={filter === id} onClick={() => setFilter(id)} key={id}>{label}</button>)}</nav></header>
          {loading ? <div className="matrix-loading"><i /><strong>Corrélation du parc en cours</strong><span>{progress} équipement{progress > 1 ? 's' : ''} analysé{progress > 1 ? 's' : ''} sur {inventory.length}</span></div> : visible.length ? <div className="matrix-table-wrap"><table className="matrix-table"><thead><tr><th>Priorité</th><th>CVE et risque</th><th>Équipement concerné</th><th>Signal</th><th>Action</th></tr></thead><tbody>{visible.map((entry) => {
            const state = urgency(entry);
            const isResolved = resolved.has(entry.key);
            return <tr key={entry.key} data-level={state.level}><td><span className="matrix-urgency" data-level={state.level}>{entry.unavailable ? 'Surveillé' : state.label}</span><b>{entry.unavailable ? '—' : `${entry.priority}/100`}</b></td><td>{entry.unavailable ? <strong className="matrix-no-cve">Aucune CVE prioritaire</strong> : <a href={`https://nvd.nist.gov/vuln/detail/${entry.vulnerability.id}`} target="_blank" rel="noreferrer">{entry.vulnerability.id} ↗</a>}<p>{entry.vulnerability.description}</p>{!entry.unavailable ? <small>Publié le {shortDate(entry.vulnerability.published)}</small> : null}</td><td><strong>{entry.asset.label}</strong><span>{entry.vendorName} · {entry.productName}</span><small>{entry.asset.version || 'Version non précisée'} · {entry.asset.exposure}</small></td><td><b className="matrix-score">{entry.vulnerability.score ?? '—'}</b><span>{entry.vulnerability.severity || 'Non classée'}</span>{entry.vulnerability.kev ? <em>Exploitation connue · CISA KEV</em> : null}</td><td><a className="matrix-fix" href={entry.advisoryUrl} target="_blank" rel="noreferrer">{entry.unavailable ? 'Voir les avis ↗' : 'Voir le correctif ↗'}</a>{!entry.unavailable ? <button type="button" onClick={() => toggleResolved(entry.key)}>{isResolved ? 'Rouvrir' : 'Marquer traité'}</button> : null}</td></tr>;
          })}</tbody></table></div> : <div className="matrix-clear"><span>✓</span><h3>{filter === 'resolved' ? 'Aucune CVE marquée comme traitée' : 'Aucune priorité dans cette vue'}</h3><p>La matrice est à jour.</p></div>}
        </section>
      </>}
    </section>
  );
}

export default function SurveillanceMatrix() {
  const [section, setSection] = useState<'plan' | 'risks'>('plan');
  return <><nav className="matrix-mode glass-panel" aria-label="Sections du plan de veille"><button type="button" aria-pressed={section === 'plan'} onClick={() => setSection('plan')}>Plan de veille</button><button type="button" aria-pressed={section === 'risks'} onClick={() => setSection('risks')}>Risques du parc</button></nav>{section === 'plan' ? <WatchPlan /> : <RiskMatrix />}</>;
}
