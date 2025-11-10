# SSH Spray

Multithreaded SSH authentication spraying tool supporting private keys and passwords against multiple hosts and users for penetration testing and security audits.

## Features

- Password and SSH key authentication testing
- Support for encrypted SSH keys with passphrases
- Multithreaded execution for speed
- Single target or bulk testing from files
- Rate limiting with configurable delays
- Thread-safe with detailed output

## Installation

```bash
pip install paramiko
```

## Usage

### Password Authentication
```bash
# Single target
python3 ssh_spray.py -m 192.168.1.10 -u root -p 'password123'

# Multiple targets and passwords
python3 ssh_spray.py -M hosts.txt -U users.txt -P passwords.txt -v
```

### SSH Key Authentication
```bash
# Unencrypted key
python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa

# Key with single passphrase
python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa -kp 'keypassword'

# Key with multiple passphrases
python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa -KP passphrases.txt
```

### Advanced Options
```bash
# Custom thread count (default: 10)
python3 ssh_spray.py -M hosts.txt -U users.txt -P passwords.txt -T 20

# Add delay to avoid rate limiting
python3 ssh_spray.py -m 172.16.1.10 -U users.txt -k id_rsa -d 0.5 -v

# Verbose output (show failed attempts)
python3 ssh_spray.py -M hosts.txt -U users.txt -P passwords.txt -v
```

## Options

| Flag | Description |
|------|-------------|
| `-m`, `--host` | Single target host |
| `-M`, `--hosts-file` | File with list of hosts |
| `-u`, `--user` | Single username |
| `-U`, `--users` | File with list of usernames |
| `-k`, `--key` | SSH private key file |
| `-kp`, `--key-passphrase` | Passphrase for encrypted key |
| `-KP`, `--key-passphrases` | File with list of key passphrases |
| `-p`, `--password` | Single password |
| `-P`, `--passwords` | File with list of passwords |
| `-t`, `--timeout` | Connection timeout in seconds (default: 5) |
| `-T`, `--threads` | Number of threads (default: 10) |
| `-d`, `--delay` | Delay in seconds between attempts (default: 0) |
| `-v`, `--verbose` | Show failed attempts |

## Notes

- SSH keys should be in PEM format. Convert OpenSSH format keys using:
  ```bash
  ssh-keygen -p -m PEM -f id_rsa
  ```
- Supports RSA, DSA, ECDSA, and Ed25519 keys
- Jobs are randomized to distribute load across hosts
- Use delays (`-d`) to avoid SSH server rate limiting

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Only use on systems you own or have explicit permission to test.
