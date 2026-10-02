#!/usr/bin/env python3
"""
pentrix-hashid: identify a hash algorithm by its format.

Matches a hash string against a signature table of regular expressions,
returning ranked candidate algorithms with a short note for each.

Usage:
    python3 hashid.py <hash>
    python3 hashid.py -f hashes.txt
    python3 hashid.py <hash> --json

Exit codes:
    0  at least one candidate found (or input processed with -f)
    1  no candidate matched / usage error
"""

import argparse
import json
import re
import sys

VERSION = "1.0.0"


def build_signatures():
    """Return the signature table as a list of dicts.

    Each entry has a compiled regex pattern, a list of candidate algorithm
    names, and a short human-readable note describing the format observed.
    Order matters: more specific (prefixed) formats come before generic
    hex-length formats so they rank first.
    """
    return [
        {
            "pattern": re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
            "candidates": ["bcrypt"],
            "note": "bcrypt modular crypt format: $2a$/$2b$/$2y$ + cost + 53-char salt/hash",
        },
        {
            "pattern": re.compile(r"^\$argon2(?:id|i|d)\$.*$"),
            "candidates": ["Argon2"],
            "note": "Argon2 password hash (PHC string format, $argon2i$/$argon2d$/$argon2id$)",
        },
        {
            "pattern": re.compile(r"^\$scrypt\$.*$"),
            "candidates": ["scrypt"],
            "note": "scrypt password hash (PHC string format, $scrypt$)",
        },
        {
            "pattern": re.compile(r"^\$7\$.*$"),
            "candidates": ["scrypt"],
            "note": "scrypt modular crypt format ($7$)",
        },
        {
            "pattern": re.compile(
                r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$"
            ),
            "candidates": ["SHA-512 crypt", "sha512crypt"],
            "note": "SHA-512 crypt ($6$): glibc/POSIX password hash, 86-char base64-ish payload",
        },
        {
            "pattern": re.compile(
                r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$"
            ),
            "candidates": ["SHA-256 crypt", "sha256crypt"],
            "note": "SHA-256 crypt ($5$): glibc/POSIX password hash, 43-char base64-ish payload",
        },
        {
            "pattern": re.compile(
                r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$"
            ),
            "candidates": ["MD5 crypt", "md5crypt"],
            "note": "MD5 crypt ($1$): classic Unix password hash, 22-char base64-ish payload",
        },
        {
            "pattern": re.compile(r"^\$pbkdf2-sha(?:1|256|512)\$.*$"),
            "candidates": ["PBKDF2"],
            "note": "PBKDF2 password hash (PHC string format, $pbkdf2-sha...$)",
        },
        {
            "pattern": re.compile(r"^\*[0-9A-F]{40}$"),
            "candidates": ["MySQL 4.1+", "MySQL5"],
            "note": "MySQL 4.1+ native password: '*' followed by 40 uppercase hex chars (SHA1(SHA1(password)))",
        },
        {
            "pattern": re.compile(r"^\$SHA\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$"),
            "candidates": ["SHA-1 crypt (Cisco)"],
            "note": "SHA-1 crypt ($SHA$): Cisco-IOS style password hash",
        },
        {
            "pattern": re.compile(r"^[a-f0-9]{32}$"),
            "candidates": ["MD5", "MD4", "MD2", "NTLM", "LM", "RIPEMD-128", "Haval-128"],
            "note": "32 lowercase hex chars: MD5, NTLM, MD4 and others share this exact format",
        },
        {
            "pattern": re.compile(r"^[A-F0-9]{32}$"),
            "candidates": ["MD5", "MD4", "NTLM", "LM"],
            "note": "32 uppercase hex chars: MD5, NTLM and others (often NTLM stored uppercase)",
        },
        {
            "pattern": re.compile(
                r"^(?=.*[a-f])(?=.*[A-F])[a-fA-F0-9]{32}$"
            ),
            "candidates": ["MD5", "MD4", "NTLM"],
            "note": "32 mixed-case hex chars: MD5, NTLM and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-f0-9]{40}$"),
            "candidates": ["SHA-1", "RIPEMD-160", "Haval-160"],
            "note": "40 lowercase hex chars: SHA-1, RIPEMD-160 and others share this format",
        },
        {
            "pattern": re.compile(
                r"^(?=.*[a-f])(?=.*[A-F])[a-fA-F0-9]{40}$"
            ),
            "candidates": ["SHA-1"],
            "note": "40 mixed-case hex chars: SHA-1 and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{56}$"),
            "candidates": ["SHA-224", "Haval-224"],
            "note": "56 hex chars: SHA-224 (SHA-2 family), Haval-224",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{64}$"),
            "candidates": ["SHA-256", "RIPEMD-256", "Haval-256", "GOST R 34.11-94"],
            "note": "64 hex chars: SHA-256 (SHA-2 family) and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{96}$"),
            "candidates": ["SHA-384"],
            "note": "96 hex chars: SHA-384 (SHA-2 family)",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{128}$"),
            "candidates": ["SHA-512", "Whirlpool"],
            "note": "128 hex chars: SHA-512 (SHA-2 family), Whirlpool",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{8}$"),
            "candidates": ["CRC32", "Adler-32"],
            "note": "8 hex chars: likely CRC32 or Adler-32 checksum",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{16}$"),
            "candidates": ["MySQL 3.x (old_password)", "DES crypt (truncated?)", "half-MD5"],
            "note": "16 hex chars: MySQL 3.x old_password, or a truncated hash",
        },
        {
            "pattern": re.compile(r"^[./A-Za-z0-9]{13}$"),
            "candidates": ["DES crypt", "descrypt"],
            "note": "13-char crypt-base64: traditional DES crypt (2-char salt + 11-char hash)",
        },
    ]


def identify(hash_string):
    """Match hash_string against the signature table.

    Returns a list of dicts with keys 'candidates' and 'note',
    in ranking order. Empty list means no format matched.
    """
    matches = []
    for sig in build_signatures():
        if sig["pattern"].match(hash_string):
            matches.append(
                {"candidates": list(sig["candidates"]), "note": sig["note"]}
            )
    return matches


def format_text(hash_string, matches):
    """Render human-readable output lines for one hash."""
    lines = ["Hash: %s" % hash_string]
    if matches:
        lines.append("Candidates:")
        for m in matches:
            lines.append("  - %s" % ", ".join(m["candidates"]))
            lines.append("    %s" % m["note"])
    else:
        lines.append("No match: format not recognized. Not a known hash format.")
    return "\n".join(lines)


def format_json(results):
    """Render results as JSON: list of {hash, candidates, notes}."""
    return json.dumps(results, indent=2)


def load_hashes_from_file(path):
    """Read one hash per line from path, skipping blank lines."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError as exc:
        raise SystemExit("error: cannot read file %r: %s" % (path, exc))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hashid.py",
        description=(
            "pentrix-hashid: identify a hash by matching it against known "
            "algorithm formats (length + character set + known prefixes). "
            "Identification is by format only, not proof: several algorithms "
            "can share the same length and charset, so all plausible "
            "candidates are listed."
        ),
        epilog=(
            "examples:\n"
            "  python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "  python3 hashid.py '$2b$12$KIX...' --json\n"
            "  python3 hashid.py -f hashes.txt\n"
            "\nNote: matching is format-based. A 32-char hex string could be "
            "MD5, NTLM, MD4 and more; the tool lists every candidate so you "
            "can test each one."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "hash",
        nargs="?",
        help="the hash string to identify (omit when using -f/--file)",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="FILE",
        help="read hashes from FILE, one per line, and identify each",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of text",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="pentrix-hashid %s" % VERSION,
    )
    args = parser.parse_args(argv)

    if args.file:
        hash_list = load_hashes_from_file(args.file)
        if not hash_list:
            print("error: file %r contains no hashes." % args.file, file=sys.stderr)
            return 1
    elif args.hash is not None:
        hash_list = [args.hash]
    else:
        parser.print_usage(sys.stderr)
        print("error: provide a hash string or use -f/--file.", file=sys.stderr)
        return 1

    results = []
    any_match = False
    for h in hash_list:
        if not h:
            print("warning: skipping empty hash.", file=sys.stderr)
            continue
        matches = identify(h)
        if matches:
            any_match = True
        results.append(
            {
                "hash": h,
                "candidates": [c for m in matches for c in m["candidates"]],
                "notes": [m["note"] for m in matches],
            }
        )

    if args.json:
        print(format_json(results))
    else:
        for r in results:
            print(format_text(r["hash"], identify(r["hash"])))
            if r is not results[-1]:
                print()

    return 0 if any_match else 1


if __name__ == "__main__":
    sys.exit(main())
