export type Cadence = 'daily' | 'weekly' | 'monthly';
export type StoryTone = 'verified' | 'contested' | 'analysis';

export type BulletinStory = {
  id: string;
  index: string;
  section: string;
  title: string;
  deck: string;
  status: string;
  tone: StoryTone;
  why: string;
  facts: string[];
  watch: string[];
  sources: { label: string; url: string; kind: string }[];
};

export const stories: Record<string, BulletinStory> = {
  graphene: {
    id: 'graphene',
    index: '01',
    section: 'Technologie & souveraineté',
    title: 'Pixel 11 : le recul de MTE rebat les cartes pour GrapheneOS',
    deck: 'Le projet a réalisé un portage partiel, mais indique ne pas pouvoir l’achever sans la protection mémoire matérielle devenue centrale dans son modèle de sécurité.',
    status: 'Faits recoupés',
    tone: 'verified',
    why: 'La dépendance à un constructeur peut devenir un risque systémique pour un système alternatif pourtant conçu pour renforcer la sécurité.',
    facts: [
      'GrapheneOS dit avoir réalisé un portage partiel avant de constater l’absence de prise en charge MTE nécessaire à ses exigences.',
      'MTE ajoute des contrôles matériels destinés à détecter ou atténuer des erreurs mémoire comme les use-after-free et dépassements de tampon.',
      'Aucune source primaire consultée ne confirme l’affirmation selon laquelle Google bloquerait volontairement des sites aux utilisateurs de GrapheneOS.',
    ],
    watch: [
      'Réponse technique de Google sur le choix matériel du Pixel 11.',
      'Décision finale de support ou non-support par GrapheneOS.',
      'Évolution des mécanismes d’attestation utilisés par les applications sensibles.',
    ],
    sources: [
      { label: 'GrapheneOS', url: 'https://discuss.grapheneos.org/d/41564-pixel-11-doesnt-meet-the-grapheneos-security-standards-and-may-be-skipped/15', kind: 'Source projet' },
      { label: 'Android Open Source Project', url: 'https://source.android.com/docs/security/test/memory-safety/arm-mte', kind: 'Documentation technique' },
    ],
  },
  moscow: {
    id: 'moscow',
    index: '02',
    section: 'Cyberconflits',
    title: 'Le directeur de la CIA à Moscou : canal de crise, signal stratégique',
    deck: 'La rencontre avec les services russes est confirmée, mais son ordre du jour ne l’est pas. OpenVigie sépare le fait diplomatique des scénarios cyber qu’il peut déclencher.',
    status: 'Fait confirmé · agenda inconnu',
    tone: 'contested',
    why: 'Une rencontre entre services peut réduire le risque d’escalade comme préparer une négociation plus large. Son opacité nourrit mécaniquement les opérations d’influence.',
    facts: [
      'Le Kremlin a confirmé une rencontre entre John Ratcliffe et ses homologues russes.',
      'Le contenu détaillé des échanges n’a pas été rendu public.',
      'Toute attribution à une opération militaire ou cyber précise reste, à ce stade, une hypothèse.',
    ],
    watch: [
      'Évolution des campagnes d’influence autour de la visite.',
      'Changements de posture cyber visant l’Ukraine, les pays baltes ou les infrastructures européennes.',
      'Annonces diplomatiques cohérentes avec un canal de désescalade.',
    ],
    sources: [
      { label: 'Associated Press', url: 'https://apnews.com/article/4efffcaac5ef6736e2b10cef73054e48', kind: 'Presse factuelle' },
      { label: 'Axios', url: 'https://www.axios.com/2026/08/25/cia-director-ratcliffe-visits-moscow', kind: 'Source complémentaire' },
    ],
  },
  apple: {
    id: 'apple',
    index: '03',
    section: 'IA & souveraineté européenne',
    title: 'Siri AI absente de l’iPhone en Europe : protection ou bras de fer ?',
    deck: 'Apple invoque des risques pour la confidentialité liés à l’interopérabilité. La Commission répond que le DMA n’interdit pas le service et que le retrait relève du choix d’Apple.',
    status: 'Positions contradictoires',
    tone: 'contested',
    why: 'Le débat ne se résume pas à “l’Europe protège” ou “l’Europe bloque”. Il oppose deux conceptions de la sécurité, de la concurrence et du contrôle des données.',
    facts: [
      'Apple annonce que Siri AI ne sera pas disponible sur iPhone et iPad dans l’Union européenne au lancement concerné.',
      'Apple présente l’interopérabilité demandée comme un risque de confidentialité et de sécurité.',
      'La Commission affirme que le DMA n’interdit aucun nouveau produit et exige une mise en conformité avec les règles applicables.',
    ],
    watch: [
      'Publication d’une architecture d’interopérabilité vérifiable.',
      'Localisation du traitement et modalités réelles de circulation des données.',
      'Audit indépendant des garanties avancées par chaque partie.',
    ],
    sources: [
      { label: 'Apple Newsroom', url: 'https://www.apple.com/ca/newsroom/2026/06/due-to-dma-siri-ai-delayed-in-eu-for-ios-27-and-ipados-27/', kind: 'Position Apple' },
      { label: 'Commission européenne', url: 'https://digital-markets-act.ec.europa.eu/citizens-and-whistleblower-portal/eu-citizens-qa_en', kind: 'Position régulateur' },
    ],
  },
  pegasus: {
    id: 'pegasus',
    index: '04',
    section: 'Surveillance',
    title: 'Pegasus : les documents internes éclairent l’industrie du zéro-clic',
    deck: 'Une analyse technique d’Amnesty décrit l’évolution des vecteurs, l’appui opérationnel aux clients et les mécanismes utilisés pour relier des infections à une même infrastructure.',
    status: 'Preuves médico-légales',
    tone: 'verified',
    why: 'Le risque ne tient pas à un logiciel isolé, mais à un marché privé de capacités offensives maintenues dans la durée pour des clients étatiques.',
    facts: [
      'Les travaux s’appuient sur des traces forensiques et des documents internes rendus publics dans le cadre d’une procédure judiciaire.',
      'Les vecteurs documentés incluent des attaques avec interaction, zéro-clic, injection réseau et accès physique.',
      'La publication décrit des capacités ; elle ne prouve pas à elle seule l’identité d’un opérateur pour chaque attaque passée.',
    ],
    watch: [
      'Nouvelles signatures forensiques et correctifs mobiles.',
      'Contrôles à l’exportation et responsabilité des fournisseurs.',
      'Accès des victimes à des mécanismes de recours indépendants.',
    ],
    sources: [
      { label: 'Amnesty Security Lab', url: 'https://securitylab.amnesty.org/latest/2026/07/inside-pegasus-the-evolution-of-the-worlds-most-notorious-spyware/', kind: 'Recherche technique' },
    ],
  },
  crypto: {
    id: 'crypto',
    index: '05',
    section: 'Cryptoactifs & criminalité',
    title: 'Rançongiciels : la bataille se déplace vers les circuits de blanchiment',
    deck: 'Europol annonce le démantèlement d’un service soupçonné d’avoir blanchi plus de 336 millions d’euros, tandis que le GAFI alerte sur la sophistication des flux illicites.',
    status: 'Sources institutionnelles',
    tone: 'verified',
    why: 'Perturber les infrastructures financières peut peser davantage sur un écosystème criminel que neutraliser un seul groupe ou un seul rançongiciel.',
    facts: [
      'Europol relie le service AudiA6 à plus de quinze enquêtes internationales et à des acteurs du rançongiciel.',
      'Le GAFI observe une complexification des usages criminels des actifs virtuels, y compris les vols liés à des acteurs étatiques.',
      'Les cryptoactifs ont aussi des usages légitimes ; l’analyse porte sur les mécanismes d’abus, pas sur une criminalisation de l’écosystème.',
    ],
    watch: [
      'Déplacement vers d’autres chaînes, stablecoins ou services de mixage.',
      'Capacité de récupération des actifs saisis.',
      'Effets concrets de la Travel Rule dans les juridictions à risque.',
    ],
    sources: [
      { label: 'Europol', url: 'https://www.europol.europa.eu/media-press/newsroom/news/ransomware-gangs-cut-eur-336-million-audia6-crypto-laundering-pipeline', kind: 'Autorité policière' },
      { label: 'GAFI / FATF', url: 'https://www.fatf-gafi.org/en/news/targeted-updated-va-vasps-2026.html', kind: 'Régulation internationale' },
    ],
  },
  cyberexpression: {
    id: 'cyberexpression',
    index: '06',
    section: 'Dossier mensuel',
    title: 'Qui gouverne la parole en ligne ? La privatisation de la cyberexpression',
    deck: 'Plateformes, app stores, clouds, moteurs de recommandation et services d’identité déterminent une part croissante des conditions d’accès au débat numérique.',
    status: 'Analyse éditoriale',
    tone: 'analysis',
    why: 'Une expression peut rester légalement autorisée tout en devenant techniquement invisible, démonétisée, déréférencée ou inaccessible faute d’infrastructure.',
    facts: [
      'Les plateformes appliquent à la fois la loi et leurs propres conditions de service.',
      'Le DSA européen impose davantage de transparence sur les décisions de modération et des voies de recours.',
      'La notion de “privatisation de la cyberexpression” est ici une grille d’analyse, pas une qualification juridique établie.',
    ],
    watch: [
      'Transparence réelle des systèmes de recommandation et de modération automatisée.',
      'Dépendance des médias et associations aux infrastructures privées.',
      'Effectivité des recours et publication des erreurs de modération.',
    ],
    sources: [
      { label: 'Commission européenne · DSA', url: 'https://digital-strategy.ec.europa.eu/en/policies/dsa-brings-transparency', kind: 'Cadre réglementaire' },
      { label: 'Nations unies', url: 'https://www.ohchr.org/Documents/Issues/Expression/Factsheet_2.pdf', kind: 'Droits humains' },
    ],
  },
};

export const issues: Record<Cadence, {
  label: string;
  date: string;
  kicker: string;
  lead: string;
  sides: string[];
  briefs: string[];
  note: string;
}> = {
  daily: {
    label: 'Édition du matin',
    date: '31.08.2026',
    kicker: 'Ce qui change aujourd’hui pour la sécurité et les libertés numériques',
    lead: 'graphene',
    sides: ['moscow', 'apple'],
    briefs: ['pegasus', 'crypto'],
    note: 'L’édition quotidienne privilégie les faits nouveaux, les signaux faibles et leurs conséquences immédiates.',
  },
  weekly: {
    label: 'Semaine 35',
    date: '24—30.08.2026',
    kicker: 'Les événements reliés entre eux, au-delà du cycle de l’actualité',
    lead: 'moscow',
    sides: ['graphene', 'pegasus'],
    briefs: ['apple', 'crypto'],
    note: 'L’hebdomadaire recoupe les récits, rapproche les signaux techniques et géopolitiques, puis indique ce qui reste inconnu.',
  },
  monthly: {
    label: 'Septembre 2026',
    date: 'N° 02',
    kicker: 'Le dossier stratégique · guerre algorithmique, surveillance et souveraineté',
    lead: 'cyberexpression',
    sides: ['apple', 'pegasus'],
    briefs: ['crypto', 'graphene'],
    note: 'Le mensuel prend du recul : un dossier vidéo, des faits vérifiés et les conséquences durables pour les droits fondamentaux.',
  },
};
