# OpenVigie - Contexte du projet et directive Qwen2.5

Ce fichier fournit à Claude le contexte nécessaire pour intervenir sur OpenVigie.
Il doit être lu avant toute modification du projet, en particulier avant une
opération liée à Ollama ou au modèle local.

## Présentation du projet

OpenVigie est une application open source de veille cybersécurité centrée sur le
parc informatique de l'utilisateur.

Le projet cherche à transformer des sources publiques et attribuées en
informations directement exploitables :

- actualités cyber récentes ;
- vulnérabilités liées aux produits et versions du parc ;
- exploitation active signalée par CISA KEV ;
- alertes et avis CERT-FR, CERT-EU, CISA et PSIRT éditeurs ;
- campagnes de menace, groupes APT et indicateurs de compromission ;
- risques liés à la chaîne d'approvisionnement logicielle ;
- bulletin, matrice de risques et alertes expliquées.

OpenVigie est un outil d'aide à la veille. Il ne doit pas être présenté comme un
scanner de vulnérabilités, une preuve autonome ou un système autorisé à modifier
automatiquement une infrastructure de production.

## Architecture fonctionnelle

Le flux général attendu est le suivant :

```text
Sources RSS/Atom et API attribuées
        ↓
Collecteur et normalisation
        ↓
Règles factuelles CVE / versions / parc / CISA KEV
        ↓
Analyse locale par Qwen2.5
        ↓
Bulletin / matrice du parc / alertes
```

Les principaux composants sont :

- `apps/web` : application Web et routes API côté interface ;
- `services/collector` : collecte RSS/Atom, NVD, CISA KEV, stockage SQLite et
  orchestration de l'analyse locale ;
- `compose.yaml` : orchestration portable de l'application, du collecteur et
  d'Ollama ;
- volume `openvigie_data` : base et données normalisées d'OpenVigie ;
- volume `openvigie_ollama` : fichiers du modèle téléchargé par Ollama.

Le bulletin constitue actuellement la vue automatique des dernières nouvelles
cyber. L'IA locale doit progressivement contribuer à sa déduplication, son
classement, ses résumés et sa mise à jour éditoriale assistée.

## Rôle de Qwen2.5

Le modèle de référence est :

```text
qwen2.5:7b-instruct
```

Qwen2.5 doit analyser uniquement les éléments fournis par le collecteur. Le
modèle ne navigue pas lui-même sur le Web et ne devient jamais une source.

Fonctions attendues :

1. regrouper les articles décrivant le même événement ;
2. classer les éléments en menace, vulnérabilité, détection, conformité ou autre ;
3. produire un résumé concis en français ;
4. extraire CVE, éditeur, produit, version, APT, malware et IOC explicitement cités ;
5. estimer la pertinence pour les équipements déclarés dans le parc ;
6. proposer une priorité et l'expliquer ;
7. conserver les noms et URL de toutes les sources utilisées ;
8. signaler les informations absentes, contradictoires ou incertaines.

## Règle de priorité fondamentale

Les règles factuelles priment toujours sur le score de l'IA.

Claude ne doit jamais modifier l'architecture de manière à permettre au modèle :

- de diminuer une priorité imposée par CISA KEV ;
- d'ignorer une correspondance confirmée entre une CVE et une version du parc ;
- de remplacer une plage de versions publiée par un éditeur ;
- d'inventer une CVE, une source, une URL, une date, une version ou un IOC ;
- de masquer l'incertitude ou la provenance d'une information.

Hiérarchie indicative :

```text
Avis primaire de l'éditeur
    + NVD / identifiant CVE
    + CISA KEV / exploitation connue
    + correspondance produit-version du parc
    > classement et score proposés par Qwen2.5
```

## Directive de configuration Docker

Qwen2.5 doit fonctionner uniquement dans Docker pour OpenVigie.

Contraintes obligatoires :

- ne pas installer Ollama ou Qwen2.5 nativement avec Homebrew, apt, winget ou un
  autre gestionnaire du système hôte ;
- ne pas écrire le modèle dans un dossier personnel de l'utilisateur ;
- conserver les fichiers du modèle dans le volume Docker
  `openvigie_ollama:/root/.ollama` ;
- utiliser le réseau interne Docker et l'adresse
  `http://ollama:11434` depuis le collecteur ;
- exposer l'API Ollama sur l'hôte uniquement via
  `127.0.0.1:${OLLAMA_PORT:-11434}:11434` ;
- préserver la compatibilité Windows, Linux et macOS ;
- ne pas ajouter de dépendance à une API d'IA distante ;
- ne jamais supprimer les volumes OpenVigie pendant une mise à jour normale.

Configuration de référence :

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    environment:
      OLLAMA_CONTEXT_LENGTH: ${OLLAMA_CONTEXT_LENGTH:-2048}
      OLLAMA_NUM_PARALLEL: ${OLLAMA_NUM_PARALLEL:-1}
    ports:
      - "127.0.0.1:${OLLAMA_PORT:-11434}:11434"
    volumes:
      - openvigie_ollama:/root/.ollama
    restart: unless-stopped

  ollama-model:
    image: ollama/ollama:latest
    environment:
      OLLAMA_HOST: http://ollama:11434
    entrypoint: ["ollama", "pull"]
    command: ["${OLLAMA_MODEL:-qwen2.5:7b-instruct}"]
```

Variables attendues dans `.env` :

```dotenv
OLLAMA_MODEL=qwen2.5:7b-instruct
OLLAMA_PORT=11434
OLLAMA_CONTEXT_LENGTH=2048
OLLAMA_NUM_PARALLEL=1
```

Le contexte de 2048 tokens et une seule inférence parallèle réduisent la pression
mémoire sur les ordinateurs personnels. Qwen2.5 7B nécessite néanmoins environ
6 Go de mémoire attribuée à Docker pour charger le modèle dans de bonnes
conditions. Sur un Mac disposant de 8 Go de RAM, éviter les applications lourdes
pendant l'inférence.

## Démarrage normal

Depuis la racine du projet :

```bash
docker compose up -d --build
```

Au premier démarrage, le service `ollama-model` télécharge
`qwen2.5:7b-instruct`. Le conteneur doit ensuite se terminer avec le code `0`.
Les démarrages suivants réutilisent le modèle présent dans le volume.

Ne pas considérer un conteneur d'initialisation arrêté avec le code `0` comme une
erreur. Il indique que le téléchargement s'est terminé correctement.

## Vérifications obligatoires

Avant d'annoncer que Qwen2.5 est opérationnel, Claude doit vérifier toutes les
étapes suivantes.

### 1. Configuration Compose

```bash
docker compose config --quiet
```

### 2. État des conteneurs

```bash
docker compose ps -a
```

Résultat attendu :

- `ollama` est démarré et sain ;
- `collector` est démarré et sain ;
- `web` est démarré ;
- `ollama-model` est terminé avec le code `0` après le téléchargement.

### 3. Présence du modèle

```bash
docker compose exec -T ollama ollama list
```

La liste doit contenir exactement le tag configuré :

```text
qwen2.5:7b-instruct
```

### 4. Véritable inférence locale

```bash
docker compose exec -T ollama \
  ollama run qwen2.5:7b-instruct "Réponds uniquement par : OpenVigie opérationnel"
```

La seule présence du modèle dans `ollama list` ne suffit pas. Une réponse réelle
doit être obtenue sans erreur mémoire et sans appel à un service distant.

### 5. API OpenVigie

```bash
curl --max-time 300 \
  "http://127.0.0.1:3000/api/ai/news-brief?cadence=daily&limit=3"
```

Vérifier un code HTTP `200`, le nom du modèle, une synthèse française non vide et
la présence des sources attribuées.

### 6. Flux structuré de tri

Le tri doit produire des résultats distincts pour :

- le bulletin dédupliqué ;
- la matrice liée au parc ;
- les alertes prioritaires ;
- les entités extraites ;
- la justification de la priorité ;
- l'origine de la priorité, `rules` ou `ai`.

## Gestion des erreurs

En cas d'échec :

- consulter `docker compose logs --tail=100 ollama` ;
- contrôler la mémoire Docker avec `docker stats --no-stream` ;
- contrôler l'espace disque de l'hôte et de Docker ;
- conserver les données et les volumes ;
- ne supprimer qu'un cache de construction ou un téléchargement partiel dont la
  corruption est confirmée ;
- ne jamais lancer `docker compose down -v` pour résoudre un problème courant ;
- ne jamais effacer globalement les images, conteneurs ou volumes qui ne sont pas
  exclusivement liés à OpenVigie ;
- documenter précisément le blocage si une action utilisateur est nécessaire.

## Consignes de modification pour Claude

Avant toute modification :

1. lire `git status --short` et préserver les changements existants ;
2. inspecter `compose.yaml`, `.env.example`, `services/collector/collector.py` et
   les routes API concernées ;
3. rester dans le périmètre demandé ;
4. ne pas écraser les documents ou livrables existants ;
5. vérifier la syntaxe Python, la configuration Compose et le build Web ;
6. tester proportionnellement au risque de la modification ;
7. expliquer les fichiers changés et les contrôles réellement effectués.

Si une migration vers un autre modèle est demandée ultérieurement, elle doit être
explicite, documentée et appliquée de façon cohérente dans `compose.yaml`,
`.env.example`, le collecteur, les tests et la documentation. Ne pas remplacer
silencieusement `qwen2.5:7b-instruct`.
