'use client';

import { useState } from 'react';
import BulletinUnified from './bulletin-unified';
import CertFrPanel from './cert-fr-panel';
import WeeklyReport from './weekly-report';
import DeepSearch from './deep-search';

type Desk = 'fil' | 'certfr' | 'hebdo' | 'recherche';

const DESKS: Array<{ id: Desk; label: string; hint: string }> = [
  { id: 'fil', label: 'Le fil', hint: 'Toutes les sources, classées' },
  { id: 'certfr', label: 'CERT-FR', hint: 'Alertes et avis officiels ANSSI' },
  { id: 'hebdo', label: 'Rapport hebdo', hint: 'Synthèse 7 jours, exportable' },
  { id: 'recherche', label: 'Recherche', hint: 'Archives multi-sources' },
];

function today() {
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'full' }).format(new Date());
}

export default function BulletinWorkspace() {
  const [desk, setDesk] = useState<Desk>('fil');
  const active = DESKS.find((item) => item.id === desk) ?? DESKS[0];

  return (
    <section className="content bulletin-workspace" id="main-content">
      <header className="bw-masthead">
        <div className="bw-dateline">
          <span>{today()}</span>
          <span>Veille cyber · sources attribuées</span>
        </div>
        <h1>OPENVIGIE</h1>
        <p className="bw-standfirst">
          Le bulletin réunit le fil de toutes les sources suivies, les avis du CERT-FR,
          la synthèse hebdomadaire et la recherche dans les archives.
        </p>
      </header>

      <nav className="bw-desks" role="tablist" aria-label="Rubriques du bulletin">
        {DESKS.map((item) => (
          <button
            type="button"
            role="tab"
            key={item.id}
            aria-selected={desk === item.id}
            onClick={() => setDesk(item.id)}
          >
            <strong>{item.label}</strong>
            <small>{item.hint}</small>
          </button>
        ))}
      </nav>

      <div className="bw-body" role="tabpanel" aria-label={active.label}>
        {desk === 'fil' ? <BulletinUnified />
          : desk === 'certfr' ? <CertFrPanel />
          : desk === 'hebdo' ? <WeeklyReport />
          : <DeepSearch />}
      </div>
    </section>
  );
}
