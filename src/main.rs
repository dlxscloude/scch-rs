use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use scch::archive;
use scch::cli::{self, Cli};
use scch::crypto;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::sync::OnceLock;

static MASTER_PASSWORD: OnceLock<String> = OnceLock::new();
static NAMEKEY_PASSWORD: OnceLock<String> = OnceLock::new();

fn main() {
    let args = Cli::parse();

    let result = if args.batch {
        do_batch(&args)
    } else if args.mode.encrypt {
        do_encrypt(&args)
    } else if args.mode.decrypt {
        do_decrypt(&args)
    } else {
        do_name(&args)
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

// ─── Password helpers ───────────────────────────────────────────────

fn get_master_password() -> String {
    if let Some(password) = MASTER_PASSWORD.get() {
        return password.clone();
    }
    cli::get_secret(
        &["SCCH_PASS", "VAULT_PASS", "VAULT_MASTER"],
        "Master password: ",
    )
}

fn get_namekey_password() -> String {
    if let Some(password) = NAMEKEY_PASSWORD.get() {
        return password.clone();
    }
    cli::get_secret(&["VAULT_NAMEKEY"], "Name-key password: ")
}

// ─── ENCRYPT ────────────────────────────────────────────────────────

fn do_encrypt(args: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let src = fs::canonicalize(shellexpand(&args.target))?;
    if !src.is_dir() {
        return Err(format!("{} is not a folder (scch encrypts whole folders)", src.display()).into());
    }

    let master = get_master_password();
    let nkey_pw = get_namekey_password();

    let stem = if let Some(ref o) = args.output {
        archive::clean_name(o)?
    } else {
        src.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archive")
            .to_string()
    };

    let outdir = fs::canonicalize(shellexpand(&args.to)).unwrap_or_else(|_| {
        let p = shellexpand(&args.to);
        let _ = fs::create_dir_all(&p);
        fs::canonicalize(&p).unwrap_or(p)
    });
    fs::create_dir_all(&outdir)?;

    let plain_name = format!("{stem}.7z");
    let target_7z = outdir.join(&plain_name);

    if args.dry_run {
        eprintln!("[dry-run] would encrypt: {}", src.display());
        eprintln!("[dry-run] output: {}", target_7z.display());
        if args.split.is_some() {
            eprintln!("[dry-run] would split archive into volumes");
        }
        if args.clean {
            eprintln!("[dry-run] would shred source folder: {}", src.display());
        }
        return Ok(());
    }

    let pb = make_spinner(&format!("encrypting: {stem}…"), args.quiet);

    // Compress directory → .7z with AES-256 + header encryption
    archive::compress_directory(&src, &target_7z, &master, args.compression, args.quiet)?;

    finish_spinner(&pb);

    // Encrypt the stem into an opaque filename token
    let token = crypto::enc_stem(&stem, &nkey_pw)?;

    // Determine produced files (handle split volumes)
    let mut vault_files: Vec<PathBuf> = if let Some(ref split_str) = args.split {
        let chunk_size = cli::parse_split_size(split_str)?;
        archive::split_archive(&target_7z, chunk_size)?
    } else {
        vec![target_7z.clone()]
    };

    // Rename plain.7z[.NNN] → token.7z[.NNN] and create SHA-256 sidecars
    let mut final_paths = Vec::new();
    for vault_path in &mut vault_files {
        let old_name = vault_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        // Replace the stem prefix with the encrypted token
        let new_name = format!("{token}{}", &old_name[stem.len()..]);
        let new_path = outdir.join(&new_name);
        fs::rename(vault_path, &new_path)?;

        // Create SHA-256 sidecar
        let sidecar = crypto::write_sha256_sidecar(&new_path)?;

        if !args.quiet {
            eprintln!("  {old_name} → {new_name} (+{})", sidecar.file_name().unwrap_or_default().to_string_lossy());
        }

        final_paths.push(new_path);
    }

    // Clean source if requested
    if args.clean {
        if cli::confirm(&format!("SHRED source folder {} ?", src.display()), args.force) {
            archive::shred_tree(&src)?;
            eprintln!("  shredded {}", src.display());
        } else {
            eprintln!("  source folder kept");
        }
    }

    if !args.quiet {
        eprintln!("done — upload the vault file(s) + .sha256 sidecar(s)");
    }

    Ok(())
}

// ─── DECRYPT ────────────────────────────────────────────────────────

fn do_decrypt(args: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let master = get_master_password();
    let target_path = shellexpand(&args.target);
    let parts = archive::resolve_parts(&target_path)?;

    // Verify checksums if --verify flag or if sidecars exist
    if args.verify {
        for p in &parts {
            crypto::verify_archive_sidecar(p, Some(&master))?;
        }
        if !args.quiet {
            eprintln!("integrity OK");
        }
    }

    // Determine output folder name
    let name = if let Some(ref o) = args.output {
        archive::clean_name(o)?
    } else {
        let nkey_pw = get_namekey_password();
        let token = archive::extract_token(&parts)?;
        crypto::dec_stem(&token, &nkey_pw)?
    };

    let outdir = shellexpand(&args.to);
    let dest = outdir.join(&name);

    if args.dry_run {
        eprintln!("[dry-run] would decrypt {} part(s) to: {}", parts.len(), dest.display());
        if args.clean {
            eprintln!("[dry-run] would delete vault archive(s) + sidecars");
        }
        return Ok(());
    }

    fs::create_dir_all(&dest)?;

    let pb = make_spinner(&format!("extracting to '{name}'…"), args.quiet);

    if archive::is_split(&parts) {
        archive::decompress_split_archive(&parts, &dest, &master, args.quiet)?;
    } else {
        archive::decompress_archive(&parts[0], &dest, &master, args.quiet)?;
    }

    finish_spinner(&pb);

    // Clean vault if requested
    if args.clean && cli::confirm("DELETE vault archive(s) + sidecars?", args.force) {
            for p in &parts {
                let _ = fs::remove_file(p);
                // Remove any sidecar files
                let sha = PathBuf::from(format!("{}.sha256", p.display()));
                let hmac = PathBuf::from(format!("{}.hmac", p.display()));
                let _ = fs::remove_file(sha);
                let _ = fs::remove_file(hmac);
            }
            eprintln!("  vault deleted");
    }

    if !args.quiet {
        eprintln!("done — extracted to {}", dest.display());
    }

    Ok(())
}

// ─── NAME ───────────────────────────────────────────────────────────

fn do_name(args: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let nkey_pw = get_namekey_password();
    let target_path = shellexpand(&args.target);
    let parts = archive::resolve_parts(&target_path)?;
    let token = archive::extract_token(&parts)?;
    let original = crypto::dec_stem(&token, &nkey_pw)?;
    println!("original name: {original}.7z");
    Ok(())
}

// ─── BATCH ──────────────────────────────────────────────────────────

fn do_batch(args: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let target_dir = fs::canonicalize(shellexpand(&args.target))?;
    if !target_dir.is_dir() {
        return Err(format!("batch target '{}' is not a directory", target_dir.display()).into());
    }

    // Pre-prompt passwords so sub-operations don't re-prompt.
    if std::env::var("SCCH_PASS").is_err()
        && std::env::var("VAULT_PASS").is_err()
        && std::env::var("VAULT_MASTER").is_err()
    {
        let pw = cli::get_secret(&[], "Master password (batch): ");
        let _ = MASTER_PASSWORD.set(pw);
    }
    if (args.mode.encrypt || args.mode.name || (args.mode.decrypt && args.output.is_none()))
        && std::env::var("VAULT_NAMEKEY").is_err()
    {
        let pw = cli::get_secret(&[], "Name-key password (batch): ");
        let _ = NAMEKEY_PASSWORD.set(pw);
    }

    if args.mode.encrypt {
        let mut folders: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&target_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && !entry.file_name().to_string_lossy().starts_with('.') {
                folders.push(path);
            }
        }
        folders.sort();

        if folders.is_empty() {
            return Err(format!("no subdirectories found in {}", target_dir.display()).into());
        }

        eprintln!(
            "Batch encrypting {} folder(s) in {}...",
            folders.len(),
            target_dir.display()
        );

        for folder in &folders {
            let mut item_args = args.clone();
            item_args.target = folder.display().to_string();
            item_args.batch = false;
            do_encrypt(&item_args)?;
        }
    } else {
        // Decrypt or Name: find all unique vault heads
        let mut seen = std::collections::HashSet::new();
        let mut vaults: Vec<PathBuf> = Vec::new();
        let re = regex::Regex::new(r"^(.+\.7z)(\.\d{3})?$").unwrap();

        let mut entries: Vec<_> = fs::read_dir(&target_dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in &entries {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".sha256") || name.ends_with(".hmac") {
                continue;
            }
            if let Some(caps) = re.captures(&name) {
                let head = caps.get(1).unwrap().as_str().to_string();
                if seen.insert(head) {
                    vaults.push(entry.path());
                }
            }
        }

        if vaults.is_empty() {
            return Err(format!("no vault archives found in {}", target_dir.display()).into());
        }

        let action = if args.mode.decrypt {
            "Batch decrypting"
        } else {
            "Batch revealing names for"
        };
        eprintln!(
            "{action} {} vault(s) in {}...",
            vaults.len(),
            target_dir.display()
        );

        for v in &vaults {
            let mut item_args = args.clone();
            item_args.target = v.display().to_string();
            item_args.batch = false;
            if args.mode.decrypt {
                do_decrypt(&item_args)?;
            } else {
                do_name(&item_args)?;
            }
        }
    }

    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────

fn shellexpand(s: &str) -> PathBuf {
    if s.starts_with('~')
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(&s[2..]);
    }
    PathBuf::from(s)
}

fn make_spinner(msg: &str, quiet: bool) -> Option<ProgressBar> {
    if quiet {
        return None;
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(120));
    Some(pb)
}

fn finish_spinner(pb: &Option<ProgressBar>) {
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
}
