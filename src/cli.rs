use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "scch",
    about = "Encrypted 7z vaults — zero-dependency standalone binary with built-in AES-256 support",
    long_about = "scch — high-security 7z vault tool\n\n\
  -e  encrypt folder(s)     -d  decrypt vault(s)     -n  reveal original name\n\
  -b  batch mode (process all subfolders or vaults in target directory)\n\
  -c  clean (-e: shred source folder | -d: delete vault after extraction)\n\
  -o  output name (archive stem for -e, folder name for -d)\n\
  -t  target dir (where the vault is saved / where extraction lands)\n\
  --split  split size, e.g. --split 1900m (Telegram 2 GB limit)\n\n\
Examples:\n\
  Single folder:  scch -e \"[10.4.26] Via Collection\"\n\
  Batch encrypt:  scch -e -b\n\
  Batch decrypt:  scch -d -b -c"
)]
pub struct Cli {
    /// Mode: encrypt (-e), decrypt (-d), or name (-n)
    #[command(flatten)]
    pub mode: Mode,

    /// Folder (with -e) or vault file (with -d/-n); defaults to '.'
    #[arg(default_value = ".")]
    pub target: String,

    /// Batch mode: process all subfolders (-e) or vaults (-d/-n) in target directory
    #[arg(short, long)]
    pub batch: bool,

    /// Output name (archive stem for -e, folder name for -d)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Target directory (where the vault is saved / where extraction lands)
    #[arg(short = 't', long = "to", default_value = ".")]
    pub to: String,

    /// -e: shred source folder | -d: delete vault after extraction
    #[arg(short, long)]
    pub clean: bool,

    /// Split size for multi-part archives, e.g. 1900m (Telegram 2 GB limit)
    #[arg(long)]
    pub split: Option<String>,

    /// Compression level (0 = store/copy [default], 1-9 = LZMA2)
    #[arg(short = 'm', long = "compression", default_value = "0")]
    pub compression: u32,

    /// Skip confirmations
    #[arg(short, long)]
    pub force: bool,

    /// Quiet mode — suppress progress output
    #[arg(short, long)]
    pub quiet: bool,

    /// Preview actions without modifying disk
    #[arg(long)]
    pub dry_run: bool,

    /// Verify archive checksums (.sha256 or legacy .hmac) before decryption
    #[arg(long)]
    pub verify: bool,
}

#[derive(clap::Args, Debug, Clone)]
#[group(required = true, multiple = false)]
pub struct Mode {
    /// Encrypt folder(s) into a vault
    #[arg(short, long)]
    pub encrypt: bool,

    /// Decrypt vault(s)
    #[arg(short, long)]
    pub decrypt: bool,

    /// Reveal the original name of a vault
    #[arg(short, long)]
    pub name: bool,
}

/// Parse a human-readable size string like "1900m", "2g", "500k" into bytes.
pub fn parse_split_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return Err("Empty split size".to_string());
    }

    let (num_str, multiplier) = if s.ends_with('g') {
        (&s[..s.len() - 1], 1024u64 * 1024 * 1024)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 1024u64 * 1024)
    } else if s.ends_with('k') {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with('b') {
        (&s[..s.len() - 1], 1u64)
    } else {
        (s.as_str(), 1u64)
    };

    let num: f64 = num_str
        .parse()
        .map_err(|e| format!("Invalid split size '{s}': {e}"))?;
    if num <= 0.0 {
        return Err(format!("Split size must be positive, got '{s}'"));
    }

    Ok((num * multiplier as f64) as u64)
}

/// Get a password from environment variables or terminal prompt.
pub fn get_secret(env_names: &[&str], prompt: &str) -> String {
    for env in env_names {
        if let Ok(val) = std::env::var(env)
            && !val.is_empty()
        {
            return val;
        }
    }
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("error: failed to read password: {e}");
        std::process::exit(1);
    })
}

/// Prompt for y/N confirmation (or auto-accept if force=true).
pub fn confirm(msg: &str, force: bool) -> bool {
    if force {
        return true;
    }
    eprint!("{msg} [y/N] ");
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim().eq_ignore_ascii_case("y")
}
