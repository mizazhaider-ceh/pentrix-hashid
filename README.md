# pentrix-hashid

![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

Identify a hash algorithm by matching it against known formats (length, character set, and known prefixes like `$2b$` or `$6$`).

Give it a hash, get back ranked candidate algorithms with a short note for each. No network, no installs beyond Python 3, standard library only.

## Features

- **Format-based identification**: regex signature table covering MD5, SHA-1, SHA-224/256/384/512, bcrypt, Argon2, scrypt, SHA-512/256 crypt, MD5 crypt, PBKDF2, MySQL 4.1+, DES crypt, CRC32, and more.
- **Ranked candidates**: when several algorithms share a format (32 hex chars can be MD5, NTLM, MD4...), all are listed so you can test each one.
- **Batch mode**: identify one hash per line from a file with `-f`.
- **JSON output**: `--json` for scripts and pipelines.
- **Zero dependencies**: only `re` and `argparse` from the standard library.

## Supported algorithms

| Format | Candidates |
|---|---|
| 32 lowercase hex | MD5, MD4, MD2, NTLM, LM, RIPEMD-128, Haval-128 |
| 32 uppercase hex | MD5, MD4, NTLM, LM |
| 32 mixed-case hex | MD5, MD4, NTLM |
| 40 hex | SHA-1, RIPEMD-160, Haval-160 |
| 56 hex | SHA-224, Haval-224 |
| 64 hex | SHA-256, RIPEMD-256, Haval-256, GOST R 34.11-94 |
| 96 hex | SHA-384 |
| 128 hex | SHA-512, Whirlpool |
| `$2a$` / `$2b$` / `$2y$` + cost + 53 chars | bcrypt |
| `$argon2i$` / `$argon2d$` / `$argon2id$` ... | Argon2 |
| `$scrypt$` ... or `$7$` ... | scrypt |
| `$6$`salt`$` + 86 chars | SHA-512 crypt |
| `$5$`salt`$` + 43 chars | SHA-256 crypt |
| `$1$`salt`$` + 22 chars | MD5 crypt |
| `$pbkdf2-sha...$` ... | PBKDF2 |
| `*` + 40 uppercase hex | MySQL 4.1+ (native password) |
| `$SHA$` ... | SHA-1 crypt (Cisco) |
| 13-char crypt base64 | DES crypt |
| 8 hex | CRC32, Adler-32 |
| 16 hex | MySQL 3.x old_password, truncated hashes |

> **Important**: identification is by format, not proof. A 32-character hex string is most often MD5, but NTLM and MD4 look exactly the same. The tool lists every plausible candidate so you can test each one (e.g. with hashcat mode numbers or John the Ripper formats).

## Install

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-hashid.git
cd pentrix-hashid
python3 --version   # any Python 3.x works
```

No `pip install`, no virtualenv, no `requirements.txt`. Just Python 3.

## Usage

```bash
# Identify a single hash
python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99

# Identify several hashes from a file (one per line)
python3 hashid.py -f hashes.txt

# Machine-readable output
python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99 --json

# Full help
python3 hashid.py --help
```

Exit codes: `0` when at least one candidate matched, `1` for no match or a usage error.

### Real examples

MD5 of "password" (from `hashlib.md5(b"password").hexdigest()`):

```bash
$ python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Candidates:
  - MD5, MD4, MD2, NTLM, LM, RIPEMD-128, Haval-128
    32 lowercase hex chars: MD5, NTLM, MD4 and others share this exact format
```

SHA-256 of "password":

```bash
$ python3 hashid.py 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Candidates:
  - SHA-256, RIPEMD-256, Haval-256, GOST R 34.11-94
    64 hex chars: SHA-256 (SHA-2 family) and others share this format
```

bcrypt:

```bash
$ python3 hashid.py '$2b$12$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy'
Hash: $2b$12$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy
Candidates:
  - bcrypt
    bcrypt modular crypt format: $2a$/$2b$/$2y$ + cost + 53-char salt/hash
```

SHA-512 crypt (from Python's `crypt` module):

```bash
$ python3 hashid.py '$6$TpozTifCuZCVBYLm$.PCBUGcsNbOnAGf3ZhWsL/W.VLoUStP.6vjAp4olNqrS/jd6th75kMc0.lWSKKgi0lrDeHskv64rEIfB0xVn01'
Hash: $6$TpozTifCuZCVBYLm$.PCBUGcsNbOnAGf3ZhWsL/W.VLoUStP.6vjAp4olNqrS/jd6th75kMc0.lWSKKgi0lrDeHskv64rEIfB0xVn01
Candidates:
  - SHA-512 crypt, sha512crypt
    SHA-512 crypt ($6$): glibc/POSIX password hash, 86-char base64-ish payload
```

Unknown / garbage input:

```bash
$ python3 hashid.py 'not-a-hash-at-all!!!'
Hash: not-a-hash-at-all!!!
No match: format not recognized. Not a known hash format.
$ echo $?
1
```

Batch file with `--json`:

```bash
$ printf '5f4dcc3b5aa765d61d8327deb882cf99\n5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n' > hashes.txt
$ python3 hashid.py -f hashes.txt --json
[
  {
    "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
    "candidates": ["MD5", "MD4", "MD2", "NTLM", "LM", "RIPEMD-128", "Haval-128"],
    "notes": ["32 lowercase hex chars: MD5, NTLM, MD4 and others share this exact format"]
  },
  {
    "hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
    "candidates": ["SHA-1", "RIPEMD-160", "Haval-160"],
    "notes": ["40 lowercase hex chars: SHA-1, RIPEMD-160 and others share this format"]
  }
]
```

## How it works

`hashid.py` holds a signature table: an ordered list of `(regex, candidate names, note)` entries. Specific formats (modular crypt prefixes like `$2b$`, `$6$`, `$argon2id$`) are checked before generic hex-length formats, so a bcrypt hash never falls through to a length guess. The first entry that matches wins its rank; every matching entry is reported, most specific first.

## License

MIT. See [LICENSE](LICENSE).
