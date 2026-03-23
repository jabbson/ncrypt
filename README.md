# ncrypt

A TypeScript CLI for OpenSSL-compatible AES-256-CBC encryption and decryption.

## Requirements

- Node.js 18+
- pnpm

## Install

```bash
pnpm install
```

## Usage

```bash
pnpm tsx crypt.ts -e|-d -k <key> -v <value>
```

### Options

| Flag | Description |
|------|-------------|
| `-e`, `--encrypt` | Encrypt the value |
| `-d`, `--decrypt` | Decrypt the value |
| `-k`, `--key` | Passphrase |
| `-v`, `--value` | Value to encrypt or decrypt |
| `-h`, `--help` | Show help |

### Examples

**Encrypt:**
```bash
pnpm tsx crypt.ts -e -k "mypassword" -v "hello world"
```

**Decrypt:**
```bash
pnpm tsx crypt.ts -d -k "mypassword" -v "U2FsdGVkX1..."
```

Each command also prints the equivalent `openssl` command to stderr for cross-verification.

## OpenSSL compatibility

Output is fully compatible with `openssl enc -aes-256-cbc -a`. To decrypt with OpenSSL:

```bash
echo '<base64>' | openssl enc -d -aes-256-cbc -a -md md5 -pass pass:'mypassword'
```

> Note: `-md md5` is required with OpenSSL 3.x, which changed the default KDF digest to SHA-256.
