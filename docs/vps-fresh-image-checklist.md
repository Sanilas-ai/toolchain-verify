# Fresh VPS from a provider image: checklist

A VPS cloned from a provider image inherits whatever the image author left behind. Run this
once after provisioning and again after every rebuild. Each item names the
`toolchain-verify host vps` rule that checks it. The audit is read-only, so it fixes nothing;
the fixes listed here are for you to apply.

```bash
sudo sshd -T > /tmp/sshd-T.txt; timedatectl show > /tmp/tdc.txt; git --version > /tmp/git.txt
sudo ufw status verbose > /tmp/ufw.txt                       # optional
sudo toolchain-verify host vps -v --sshd-t /tmp/sshd-T.txt --timedatectl /tmp/tdc.txt \
  --git-version /tmp/git.txt --ufw-status /tmp/ufw.txt --listen-policy listen.toml
```

Running as root lets the sudoers and `/root/.ssh` checks read their files. As a normal user
they report which files could not be read (info) instead of guessing.

| # | Item | Rule(s) | Fix |
| --- | --- | --- | --- |
| 1 | SSH host keys were generated on **this** machine: no template comment (`root@<image-builder>`), not older than the first boot, ed25519 present, no DSA | `host.ssh-hostkeys-template` | `rm /etc/ssh/ssh_host_*; ssh-keygen -A`, then update `known_hosts` on the clients. Keep `ssh_deletekeys: true` in cloud-init |
| 2 | No password login: `PasswordAuthentication no`, **and** keyboard-interactive off when PAM is on (`KbdInteractiveAuthentication` / the old `ChallengeResponseAuthentication` with `UsePAM yes` still asks for the password), no `PermitRootLogin yes`. The first value wins, so check cloud-init drop-ins such as `50-cloud-init.conf` | `host.sshd-effective` | a `00-hardening.conf` drop-in with `PasswordAuthentication no`, `KbdInteractiveAuthentication no` and `PermitRootLogin prohibit-password` (or `no`) |
| 3 | No passwordless `sudo ALL` (cloud-init writes `90-cloud-init-users` with `NOPASSWD:ALL`) | `host.sudoers-nopasswd` | require a password, or limit `NOPASSWD` to a command list |
| 4 | `authorized_keys` hygiene for root and users: no DSA, no RSA below 2048 bits, no key authorized twice or shared between accounts, root keys restricted with `from=` / `command=` | `host.authorized-keys-hygiene` | remove stale keys; one key per person; `from="198.51.100.0/24"` on root keys, or no root keys at all |
| 5 | Running kernel is the newest installed one and has its security updates | `host.kernel-stale`, `kernel.floor` | `apt full-upgrade && reboot` |
| 6 | Unattended security updates are on | `host.no-auto-updates` | `apt install unattended-upgrades; dpkg-reconfigure -plow unattended-upgrades` |
| 7 | Default-deny inbound firewall | `host.firewall-off` | `ufw default deny incoming; ufw allow 22/tcp; ufw enable` |
| 8 | Only intended ports listen outside loopback | `host.listeners-policy`, `host.ssh-exposed`, `net.exposed` | write an allowlist (`[host.listen] allowed = ["22/tcp", "443/udp"]`) and bind everything else to `127.0.0.1` |
| 9 | Brute-force protection on exposed SSH | `host.no-bruteforce-protection` | fail2ban, sshguard, crowdsec or `ufw limit 22/tcp` |
| 10 | Clock is synchronised (TLS, TOTP and log correlation depend on it) | `host.ntp-unsynced` | `timedatectl set-ntp true` (systemd-timesyncd) or chrony |
| 11 | git is patched before any recursive clone | `host.git-cve-2026-111760` | upgrade git |

Listener policy file for `--listen-policy` (or the same `[host.listen]` section in the
manifest):

```toml
[host.listen]
allowed = ["22/tcp", "443/udp"]
```

Without a policy, `host.listeners-policy` prints one info line with the inventory of
non-loopback listeners. UDP sockets in the ephemeral port range are skipped, as in
`net.*`, because they are almost always client sockets. A tunnel on a default port inside
that range (WireGuard's 51820) is therefore not listed; check it with `ss -ulnp`.

## Channel: vanilla WireGuard on a DPI path

This section is guidance only. toolchain-verify has no detector for it and does not plan one.

Vanilla WireGuard is easy to classify on a path with DPI (for example TSPU in Russia). Its
handshake messages have fixed types and fixed lengths, the first bytes have little variety,
and there is no TLS/QUIC envelope. Expect the tunnel to be throttled or cut, sometimes only
after the handshake.

- Do not depend on vanilla WireGuard as the only channel to the VPS from such a path.
- If you need a WireGuard-family tunnel, use **AmneziaWG** (non-canonical message types,
  junk packets, variable handshake lengths). Set your own junk/header parameters, not a
  widely shared default, and keep them in the operators' vault, not in a public repo.
- Alternatively, wrap the tunnel in a TLS/QUIC-like transport on 443 (UDP or TCP). Make the
  SNI, ALPN and certificate plausible, and remember that the certificate needs correct time
  (item 10).
- Obfuscation hides the handshake, but it does not stop IP blocking, traffic-volume and
  timing analysis, or active probing. Keep a **fallback channel** on a different transport
  and address, and keep console access through the provider for when both fail.
- Allow only the chosen ports in the firewall and in the listener policy (items 7–8).
