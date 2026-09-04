# OpenVigie — Déploiement Cross-Platform

OpenVigie est une plateforme de **veille cybersécurité** avec IA locale (Qwen2.5). Deploy en 1 commande sur **Windows, macOS ou Linux**.

## 🚀 Démarrage Rapide

### Prérequis
- **Docker Desktop** installé
  - [Windows](https://docs.docker.com/desktop/install/windows-install/)
  - [macOS](https://docs.docker.com/desktop/install/mac-install/)
  - [Linux](https://docs.docker.com/engine/install/)
- **8 GB de RAM minimum** pour Qwen2.5
- **5 GB d'espace disque** pour les images

### Lancer le projet (Tous les OS)

```bash
# 1. Cloner le repo
git clone https://github.com/Swapshadow/openvigie.git
cd openvigie

# 2. Démarrer la stack
docker compose -f docker-compose.prod.yml up -d

# 3. Attendre 2-3 min le démarrage d'Ollama...
docker compose -f docker-compose.prod.yml logs -f ollama

# 4. Accéder à l'application
# → http://localhost:3000
```

## 📋 Détails par OS

### macOS
```bash
# Intel ou Apple Silicon (M1/M2/M3) — compatible
docker --version  # Vérifier Docker Desktop actif
docker compose -f docker-compose.prod.yml up -d
open http://localhost:3000
```

### Windows (PowerShell)
```powershell
# Docker Desktop doit tourner
docker --version
docker compose -f docker-compose.prod.yml up -d
# Ouvrir http://localhost:3000 dans le navigateur
```

### Linux (Ubuntu/Debian)
```bash
# Installer Docker (si pas déjà fait)
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Démarrer
sudo docker compose -f docker-compose.prod.yml up -d
# http://localhost:3000
```

## 🛑 Arrêter l'application

```bash
docker compose -f docker-compose.prod.yml down
```

## 📊 Architecture

- **Web** (Next.js) → http://localhost:3000
- **Collector** (Python) → http://localhost:8787
- **Ollama** (Qwen2.5 3b) → http://localhost:11434

## 🆘 Problèmes courants

### Docker ne démarre pas
```bash
# Vérifier que Docker Desktop est lancé
docker ps
```

### Disque plein
```bash
# Nettoyer
docker system prune -a --volumes
```

### Ollama très lent
- Premier démarrage : ~5-10 min (télécharge le modèle)
- Ensuite : ~2 min de warm-up
- **Besoin de 8 GB RAM minimum**

## 📚 Documentation complète

Voir [DEPLOYMENT.md](DEPLOYMENT.md) pour la configuration avancée.

## 📦 Images Docker

Images disponibles sur Docker Hub :
```bash
docker pull swapshadow/openvigie-web:latest
docker pull swapshadow/openvigie-collector:latest
```

---

**Version**: 1.0.0 | **Modèle IA**: Qwen2.5 3b-instruct (local)
