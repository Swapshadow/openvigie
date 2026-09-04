'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
type AlertStatus = 'active' | 'patched' | 'ignored' | 'snoozed';
type AlertAction = 'patch' | 'ignore' | 'snooze' | 'reopen';

type AlertMatch = {
  articleId: string;
  title: string;
  url: string;
  source: string;
  category: string;
  publishedAt: string | null;
  cves: string[];
  kevCves: string[];
  versionMentioned: boolean;
  reasons: string[];
};

type TimelineEntry = { action: string; note: string; at: string | null };

type WatchAlert = {
  id: string;
  label: string;
  severity: Severity;
  effectiveSeverity: Severity;
  escalated: boolean;
  vendor: string;
  product: string;
  version: string;
  keywords: string[];
  status: AlertStatus;
  snoozedUntil: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  matches: AlertMatch[];
  matchCount: number;
  timeline: TimelineEntry[];
};

type AlertsResponse = {
  generatedAt: string;
  window: { days: number; articles: number };
  severities: Severity[];
  grouped: Record<Severity, WatchAlert[]>;
  alerts: WatchAlert[];
  stats: Record<string, number>;
  rules: { precedence: string; kevStatus: string };
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critique',
  high: 'Élevée',
  medium: 'Moyenne',
  low: 'Faible',
};

const STATUS_LABEL: Record<AlertStatus, string> = {
  active: 'Active',
  patched: 'Corrigée',
  ignored: 'Ignorée',
  snoozed: 'Reportée',
};

const ACTION_LABEL: Record<string, string> = {
  created: 'Créée',
  patch: 'Corrigée',
  ignore: 'Ignorée',
  snooze: 'Reportée 7 j',
  reopen: 'Réouverte',
};

function formatDate(value: string | null, withTime = false) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    ...(withTime ? { timeStyle: 'short' as const } : {}),
  }).format(date);
}

export default function WatchAlerts() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [severity, setSeverity] = useState<Severity>('high');
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [version, setVersion] = useState('');
  const [keywords, setKeywords] = useState('');
  const [formError, setFormError] = useState('');

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/api/watch-alerts', { cache: 'no-store', signal });
      const payload = await response.json() as AlertsResponse & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Alertes indisponibles.');
      setData(payload);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      setError(caught instanceof Error ? caught.message : 'Alertes indisponibles.');
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    // Defer past the synchronous effect body so the first setState isn't a cascading render.
    const timer = window.setTimeout(() => void load(controller.signal), 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [load]);

  const createAlert = async () => {
    setFormError('');
    if (!label.trim()) { setFormError('Donne un nom à l’alerte.'); return; }
    if (!vendor.trim() && !product.trim() && !keywords.trim()) {
      setFormError('Renseigne au moins un éditeur, un produit ou un mot-clé.');
      return;
    }
    setBusy('create');
    try {
      const response = await fetch('/api/watch-alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: label.trim(),
          severity,
          vendor: vendor.trim(),
          product: product.trim(),
          version: version.trim(),
          keywords: keywords.split(',').map((item) => item.trim()).filter(Boolean),
        }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Création refusée.');
      setLabel(''); setVendor(''); setProduct(''); setVersion(''); setKeywords('');
      setFormOpen(false);
      await load();
    } catch (caught) {
      setFormError(caught instanceof Error ? caught.message : 'Création refusée.');
    } finally {
      setBusy('');
    }
  };

  const act = async (id: string, action: AlertAction) => {
    setBusy(id);
    try {
      await fetch('/api/watch-alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action }),
      });
      await load();
    } finally {
      setBusy('');
    }
  };

  const remove = async (id: string) => {
    setBusy(id);
    try {
      await fetch(`/api/watch-alerts?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      await load();
    } finally {
      setBusy('');
    }
  };

  const severities = useMemo(() => data?.severities ?? (['critical', 'high', 'medium', 'low'] as Severity[]), [data]);
  const stats = data?.stats ?? {};

  return (
    <div className="alert-board">
      <div className="alert-board-toolbar">
        <div className="alert-kpis">
          {severities.map((name) => (
            <article key={name} data-severity={name}>
              <span>{SEVERITY_LABEL[name]}</span>
              <strong>{stats[name] ?? 0}</strong>
            </article>
          ))}
          <article data-severity="info">
            <span>Actives · avec match</span>
            <strong>{stats.active ?? 0} · {stats.matching ?? 0}</strong>
          </article>
        </div>
        <div className="alert-board-actions">
          <button type="button" onClick={() => setFormOpen((value) => !value)}>
            {formOpen ? 'Fermer' : '+ Nouvelle alerte'}
          </button>
          <button type="button" onClick={() => void load()} disabled={loading}>
            {loading ? 'Contrôle…' : 'Re-vérifier'}
          </button>
        </div>
      </div>

      {data ? (
        <p className="alert-precedence">
          <strong>Règle :</strong> {data.rules.precedence} Fenêtre d’auto-contrôle : {data.window.days} jours
          ({data.window.articles} articles) · CISA KEV {data.rules.kevStatus === 'online' ? 'en ligne' : 'dégradé'}.
        </p>
      ) : null}

      {formOpen ? (
        <form
          className="alert-form"
          onSubmit={(event) => { event.preventDefault(); void createAlert(); }}
        >
          <label>Nom de l’alerte
            <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Pare-feu périmétrique" />
          </label>
          <label>Sévérité
            <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)}>
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map((name) => (
                <option value={name} key={name}>{SEVERITY_LABEL[name]}</option>
              ))}
            </select>
          </label>
          <label>Éditeur
            <input value={vendor} onChange={(event) => setVendor(event.target.value)} placeholder="Fortinet" />
          </label>
          <label>Produit
            <input value={product} onChange={(event) => setProduct(event.target.value)} placeholder="FortiOS" />
          </label>
          <label>Version
            <input value={version} onChange={(event) => setVersion(event.target.value)} placeholder="7.4.7" />
          </label>
          <label className="wide">Mots-clés (séparés par des virgules)
            <input value={keywords} onChange={(event) => setKeywords(event.target.value)} placeholder="ssl-vpn, pre-auth" />
          </label>
          {formError ? <p className="alert-form-error">{formError}</p> : null}
          <button type="submit" disabled={busy === 'create'}>
            {busy === 'create' ? 'Création…' : 'Créer l’alerte'}
          </button>
        </form>
      ) : null}

      {error ? (
        <div className="alert-empty" data-error="true">
          <strong>Alertes indisponibles</strong>
          <p>{error}</p>
        </div>
      ) : loading && !data ? (
        <div className="alert-empty"><p>Contrôle du bulletin en cours…</p></div>
      ) : (data?.alerts.length ?? 0) === 0 ? (
        <div className="alert-empty">
          <strong>Aucune alerte définie</strong>
          <p>Crée une alerte : le collecteur confronte automatiquement le bulletin à chaque nouvelle collecte.</p>
        </div>
      ) : (
        severities.map((name) => {
          const group = data?.grouped[name] ?? [];
          if (group.length === 0) return null;
          return (
            <section className="alert-group" key={name} data-severity={name}>
              <header>
                <h3>{SEVERITY_LABEL[name]}</h3>
                <span>{group.length} alerte{group.length > 1 ? 's' : ''}</span>
              </header>
              <ul>
                {group.map((alert) => (
                  <li key={alert.id} className="alert-card" data-status={alert.status}>
                    <div className="alert-card-head">
                      <div>
                        <strong>{alert.label}</strong>
                        <span className="alert-scope">
                          {[alert.vendor, alert.product, alert.version].filter(Boolean).join(' · ') || 'Mots-clés seuls'}
                        </span>
                      </div>
                      <div className="alert-badges">
                        <span className="alert-status" data-status={alert.status}>{STATUS_LABEL[alert.status]}</span>
                        {alert.escalated ? (
                          <span className="alert-escalated" title="Élevée par CISA KEV">
                            ↑ KEV · {SEVERITY_LABEL[alert.severity]} → {SEVERITY_LABEL[alert.effectiveSeverity]}
                          </span>
                        ) : null}
                      </div>
                    </div>

                    {alert.keywords.length > 0 ? (
                      <ul className="alert-keywords">
                        {alert.keywords.map((word) => <li key={word}>{word}</li>)}
                      </ul>
                    ) : null}

                    {alert.status === 'active' ? (
                      alert.matchCount > 0 ? (
                        <div className="alert-matches">
                          <p><strong>{alert.matchCount}</strong> correspondance{alert.matchCount > 1 ? 's' : ''} dans le bulletin</p>
                          <ul>
                            {alert.matches.map((match) => (
                              <li key={match.articleId}>
                                <a href={match.url} target="_blank" rel="noreferrer noopener">{match.title}</a>
                                <span>{match.source} · {formatDate(match.publishedAt)}</span>
                                <em>{match.reasons.join(' · ')}</em>
                                {match.cves.length > 0 ? (
                                  <div className="alert-match-cves">
                                    {match.cves.slice(0, 6).map((cve) => (
                                      <b key={cve} data-kev={match.kevCves.includes(cve)}>{cve}</b>
                                    ))}
                                  </div>
                                ) : null}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : (
                        <p className="alert-nomatch">Aucune correspondance dans la fenêtre courante.</p>
                      )
                    ) : (
                      <p className="alert-nomatch">
                        Auto-contrôle suspendu ({STATUS_LABEL[alert.status].toLowerCase()}
                        {alert.snoozedUntil ? ` jusqu’au ${formatDate(alert.snoozedUntil)}` : ''}).
                      </p>
                    )}

                    <div className="alert-card-actions">
                      {alert.status === 'active' ? (
                        <>
                          <button type="button" disabled={busy === alert.id} onClick={() => void act(alert.id, 'patch')}>Patché</button>
                          <button type="button" disabled={busy === alert.id} onClick={() => void act(alert.id, 'snooze')}>Reporter 7 j</button>
                          <button type="button" disabled={busy === alert.id} onClick={() => void act(alert.id, 'ignore')}>Ignorer</button>
                        </>
                      ) : (
                        <button type="button" disabled={busy === alert.id} onClick={() => void act(alert.id, 'reopen')}>Réouvrir</button>
                      )}
                      <button type="button" className="alert-delete" disabled={busy === alert.id} onClick={() => void remove(alert.id)}>Supprimer</button>
                    </div>

                    {alert.timeline.length > 0 ? (
                      <ol className="alert-timeline">
                        {alert.timeline.map((entry, index) => (
                          <li key={`${entry.at}-${index}`}>
                            <b>{ACTION_LABEL[entry.action] ?? entry.action}</b>
                            <time>{formatDate(entry.at, true)}</time>
                            {entry.note ? <span>{entry.note}</span> : null}
                          </li>
                        ))}
                      </ol>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          );
        })
      )}
    </div>
  );
}
