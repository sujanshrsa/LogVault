# LogVault 🗂️

A minimal log-download web server packaged in a **scratch** Docker image (~5 MB).

## Architecture

```
golang:alpine  ─── build stage (compiles static binary)
     │
     └── scratch ── runtime stage (zero OS, just the binary)
```

## Quick Start

### Option A — Docker Compose (recommended)
```bash
mkdir -p logs
cp /var/log/*.log logs/          # put your logs here

docker compose up -d
open http://localhost:8080
```

### Option B — Docker CLI
```bash
# Build
docker build -t logvault .

# Run (mount your log directory)
docker run -d \
  --name logvault \
  -p 8080:8080 \
  -v /path/to/your/logs:/app/logs:ro \
  logvault
```

### Option C — Named Volume
```bash
docker run -d \
  --name logvault \
  -p 8080:8080 \
  -v logvault-logs:/app/logs \
  logvault

# Populate the volume
docker run --rm \
  -v logvault-logs:/app/logs \
  -v /var/log:/src:ro \
  alpine sh -c "cp /src/*.log /app/logs/"
```

## Endpoints

| Endpoint           | Description                    |
|--------------------|-------------------------------|
| `GET /`            | HTML file browser              |
| `GET /download/:f` | Download a specific log file  |
| `GET /health`      | JSON health check (`200 OK`)  |

## Image Size

| Stage         | Base          | Approx. Size |
|---------------|---------------|--------------|
| Build         | golang:alpine | ~350 MB      |
| **Final**     | **scratch**   | **~5 MB**    |

## Security Notes

- The binary is compiled with `CGO_ENABLED=0` for a fully static, dependency-free binary.
- Mount logs as `:ro` (read-only) to prevent the app from modifying your logs.
- Path traversal (`../`) is rejected by the download handler.
- No shell, no OS utilities inside the final image — minimal attack surface.
