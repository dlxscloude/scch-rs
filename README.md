# scch

`scch` is a standalone Rust CLI for creating and opening encrypted 7z
archives, with zero external runtime dependencies. Its AES-256 encryption is
built in; no external archive tool is required.

Store mode (`-m 0`) is the default: it copies files without compression. This
avoids unnecessary memory pressure and helps prevent OOM kills when processing
large media folders. Use `-m 1` through `-m 9` to enable LZMA2 compression.

## Build

```sh
cargo build --release
```

The executable is `target/release/scch`.

## Usage

```sh
scch -e /path/to/folder              # Encrypt a folder
scch -d /path/to/vault.7z            # Decrypt a vault
scch -d --verify /path/to/vault.7z   # Verify SHA-256 sidecars before decrypting
scch -e --split 1900m /path/to/folder # Split for Telegram-sized uploads
```

Passwords are prompted for interactively, or can be supplied through
`SCCH_PASS` and `VAULT_NAMEKEY`. Keep passwords and generated vault files safe;
the `.sha256` sidecars provide integrity checks, not secrecy.
