---
audience: developer
ordering_override: -45
---

# Upload CLI (harbor-upload)

A tiny CLI tool for deploying site folders to Cloudflare Pages webspaces. It tars the folder, uploads it to the deploy API, and waits for the deployment to complete.

## Installation

```bash
cargo install --git https://git.plan.ai/plan-ai/mac-mgmt harbor-upload
```

## Usage

```bash
# Minimal (token and URL from env, webspace from token scope)
export HARBOR_TOKEN="your-deploy-token"
export HARBOR_URL="https://your-server.example.com"
harbor-upload ./dist

# Explicit arguments
harbor-upload ./dist \
  --token YOUR_TOKEN \
  --url https://your-server.example.com \
  --webspace-id 550e8400-e29b-41d4-a716-446655440000

# Don't wait for deploy to finish
harbor-upload ./dist --no-wait
```

## Arguments

| Argument | Env Variable | Required | Description |
|----------|-------------|----------|-------------|
| `PATH` | — | Yes | Directory to upload |
| `--token` | `HARBOR_TOKEN` | Yes | Deploy token |
| `--url` | `HARBOR_URL` | Yes | Server URL |
| `--webspace-id` | `HARBOR_WEBSPACE_ID` | No | Webspace UUID. Auto-detected from token scope if omitted. |
| `--poll-interval` | — | No | Seconds between status polls (default: 3) |
| `--no-wait` | — | No | Exit after upload without waiting |

## Auto-detecting Webspace

If `--webspace-id` is not specified, the CLI calls `GET /api/v1/deploy/whoami` to check the token's scope. If the token is scoped to a single webspace, that webspace is used automatically.

For tokens scoped to "All webspaces", you must specify `--webspace-id`.

## Example Output

```
$ harbor-upload ./dist
No --webspace-id specified, checking token scope...
Using token's scoped webspace: my-site (550e8400-...)
Packaging ./dist...
Tarball size: 45632 bytes (44.6 KB)
Uploading to webspace 550e8400-...
Deployment abc123 started (status: uploading)
Waiting for deployment...
Status: deploying
Status: success
Deployment successful!
{"deployment_id":"abc123","status":"success"}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Deploy
  env:
    HARBOR_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    HARBOR_URL: ${{ vars.SERVER_URL }}
  run: harbor-upload ./dist
```

### GitLab CI

```yaml
deploy:
  script:
    - harbor-upload ./dist
  variables:
    HARBOR_TOKEN: $DEPLOY_TOKEN
    HARBOR_URL: $SERVER_URL
```
