# Docker seed hub

```bash
cd hacash-l2-protocol

# Single seed hub on :9090
docker compose up --build

# Seed + peer hub (multi profile)
docker compose --profile multi up --build
```

Point agents at `http://127.0.0.1:9090`.

Fullnode on host (optional):

```bash
export HACASH_L2_FULLNODE=host.docker.internal:8080
docker compose up --build
```

```bash
curl -s http://127.0.0.1:9090/v1/agent/v1/manifest | head
```
