# GitHub Actions auto-deploy — one-time setup

The workflow `.github/workflows/deploy.yml` SSHes into the VPS on every push to
`main` and runs the existing `/var/www/lendifyme/deploy.sh`. It needs an SSH key
and passwordless sudo for the few `sudo` commands inside `deploy.sh`.

## 1. Create a dedicated deploy SSH key (run locally or on the server)

```bash
ssh-keygen -t ed25519 -f ~/deploy_key -N "" -C "github-actions-deploy"
```

Add the **public** key to the deploy user's authorized_keys on the VPS
(the user must be `derek`, since deploy.sh chowns to derek and git-pulls):

```bash
# on the VPS, as derek:
cat >> ~/.ssh/authorized_keys < deploy_key.pub   # paste/append the .pub contents
```

## 2. Add GitHub repo secrets

Repo → Settings → Secrets and variables → Actions → New repository secret:

| Secret            | Value                                              |
|-------------------|----------------------------------------------------|
| `SSH_PRIVATE_KEY` | full contents of the **private** `~/deploy_key`    |
| `SSH_HOST`        | server IP or hostname (e.g. `lendifyme.com`)       |
| `SSH_USER`        | `derek`                                            |
| `SSH_PORT`        | only if SSH isn't on 22 (otherwise skip)           |

## 3. Passwordless sudo for the deploy commands

`deploy.sh` uses `sudo` for chown / `sudo -u www-data` / `systemctl restart`.
CI can't type a password, so grant NOPASSWD for exactly those. On the VPS:

```bash
sudo visudo -f /etc/sudoers.d/lendifyme-deploy
```

Add (adjust paths if needed):

```
derek ALL=(ALL) NOPASSWD: /bin/chown -R derek\:derek /var/www/lendifyme, \
                          /bin/chown -R www-data\:www-data /var/www/lendifyme, \
                          /bin/systemctl restart gunicorn-lendifyme, \
                          /usr/bin/sudo -u www-data *
```

> Tip: test with `sudo -n chown -R derek:derek /var/www/lendifyme` — `-n`
> (non-interactive) must succeed without prompting.

## 4. Test

- Manual: GitHub → Actions → "Deploy to production" → **Run workflow**.
- Auto: push any commit to `main` and watch the Actions tab.

If it fails, the Actions log shows the exact SSH/deploy.sh output.
