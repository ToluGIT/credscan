# Deploying the public CredScan GUI

This deploys the hardened, upload-only public GUI (`Dockerfile.gui`,
`CREDSCAN_PUBLIC=1`) to Fly.io and points `credscan.tolubanji.com` at it. The
public image has no filesystem access, no boto3, and no path/history/validation,
so it is safe to expose. See [SECURITY.md](../SECURITY.md) for the threat model.

## Prerequisites (one time)

```bash
# 1. Install the Fly CLI
curl -L https://fly.io/install.sh | sh        # adds flyctl to your PATH

# 2. Log in (opens a browser)
fly auth login
```

## First deploy

From the repo root (the directory with `fly.toml`):

```bash
# Create the app without deploying yet (uses the existing fly.toml).
# Answer "No" if asked to overwrite fly.toml or add a database/redis.
fly launch --no-deploy

# Build Dockerfile.gui and ship it.
fly deploy
```

When it finishes, `fly open` opens the live app at `https://credscan-gui.fly.dev`
(or whatever app name you confirmed). Verify it works there first.

## Custom domain: credscan.tolubanji.com

```bash
# Ask Fly to provision a TLS cert for the subdomain.
fly certs add credscan.tolubanji.com
```

Fly prints the DNS records to add. At your domain registrar (where
`tolubanji.com` is managed), add the record it asks for, normally:

```
Type    Name        Value
CNAME   credscan    credscan-gui.fly.dev
```

(If the registrar will not CNAME a subdomain, use the A/AAAA addresses Fly
prints instead.) Then check issuance:

```bash
fly certs show credscan.tolubanji.com    # wait for "Status: Ready"
```

DNS + cert issuance usually takes a few minutes. Once ready,
`https://credscan.tolubanji.com` serves the public GUI.

## Updating after a change

```bash
git push            # push your commits first
fly deploy          # rebuild + ship the new image
```

## Notes

- Cost: the app uses a shared-cpu 512 MB VM and `auto_stop_machines`, so it
  scales to zero when idle. Fly's free allowance covers a demo of this size.
- The deployed image is public mode only. Never deploy `Dockerfile.gui.local`
  (the full-power image) to a public host.
- The link in the GUI top bar (`[ guide ]`) and `/guide` work on the deployed
  site with no extra config.
