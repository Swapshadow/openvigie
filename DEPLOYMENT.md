# OpenVigie Docker Deployment

## Quick Start (Production)

```bash
# Pull the latest images
docker pull swapshadow/openvigie-web:latest
docker pull swapshadow/openvigie-collector:latest

# Run with docker-compose (production optimized)
docker compose -f docker-compose.prod.yml up -d

# Check status
docker compose -f docker-compose.prod.yml ps
```

## Images

- **Web**: `swapshadow/openvigie-web:latest`
- **Collector**: `swapshadow/openvigie-collector:latest`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Host                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │     Web      │  │  Collector   │  │    Ollama    │       │
│  │  (port 3000) │  │ (port 8787)  │  │(port 11434)  │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                 │                  │                │
│         └─────────────────┼──────────────────┘                │
│                           │                                   │
│                   ┌───────▼────────┐                          │
│                   │  Shared Data   │                          │
│                   │  (SQLite, etc) │                          │
│                   └────────────────┘                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Environment Variables

```bash
# .env file
OLLAMA_MODEL=qwen2.5:3b-instruct
OLLAMA_PORT=11434
OLLAMA_CONTEXT_LENGTH=2048
OLLAMA_NUM_PARALLEL=1
```

## Logs

```bash
# View all logs
docker compose -f docker-compose.prod.yml logs -f

# View specific service
docker compose -f docker-compose.prod.yml logs -f web
```

## Health Checks

Each service has built-in health checks:
- **Web**: HTTP 200 on `http://localhost:3000`
- **Collector**: HTTP 200 on `http://localhost:8787/health`
- **Ollama**: HTTP 200 on `http://localhost:11434/api/tags`

## CI/CD Pipeline

GitHub Actions automatically:
1. Builds Docker images on push to `main`
2. Tags with branch name, commit SHA, and `latest`
3. Pushes to Docker Hub under `swapshadow/`

**Required GitHub Secrets**:
- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub access token

## Local Development

```bash
# Use the development compose
docker compose up -d

# Build with local changes
docker compose build --no-cache web
docker compose up -d web
```

## Production Notes

- Images run as non-root user (`nextjs` for web, `collector` for collector)
- Multi-stage builds optimize image size
- Health checks enable automatic container restart
- All services restart unless manually stopped
- Volumes persist data across container restarts
