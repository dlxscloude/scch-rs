use crate::error::ScchError;
use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
use sevenz_rust2::*;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ─── MultiFileReader for split-volume decompression ─────────────────

/// Reads across multiple files as if they were concatenated.
/// Used to decompress split .7z.001 / .7z.002 / ... volumes.
pub struct MultiFileReader {
    paths: Vec<PathBuf>,
    part_sizes: Vec<u64>,
    total_len: u64,
    pos: u64,
    current_file: Option<File>,
    current_idx: usize,
}

impl MultiFileReader {
    pub fn new(paths: Vec<PathBuf>) -> std::io::Result<Self> {
        let mut part_sizes = Vec::new();
        let mut total_len = 0u64;
        for p in &paths {
            let len = fs::metadata(p)?.len();
            part_sizes.push(len);
            total_len += len;
        }
        Ok(Self {
            paths,
            part_sizes,
            total_len,
            pos: 0,
            current_file: None,
            current_idx: 0,
        })
    }

    fn locate(&self, pos: u64) -> (usize, u64) {
        let mut accum = 0u64;
        for (i, &size) in self.part_sizes.iter().enumerate() {
            if pos < accum + size {
                return (i, pos - accum);
            }
            accum += size;
        }
        (
            self.paths.len().saturating_sub(1),
            pos.saturating_sub(accum),
        )
    }
}

impl Read for MultiFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total_len || buf.is_empty() {
            return Ok(0);
        }
        let (idx, offset) = self.locate(self.pos);
        if self.current_file.is_none() || self.current_idx != idx {
            let mut file = File::open(&self.paths[idx])?;
            file.seek(SeekFrom::Start(offset))?;
            self.current_file = Some(file);
            self.current_idx = idx;
        }

        let remaining = self.part_sizes[idx].saturating_sub(offset);
        let max_read = (buf.len() as u64).min(remaining) as usize;
        if max_read == 0 {
            self.current_file = None;
            self.current_idx = idx + 1;
            return self.read(buf);
        }

        let n = self
            .current_file
            .as_mut()
            .unwrap()
            .read(&mut buf[..max_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for MultiFileReader {
    fn seek(&mut self, seek: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match seek {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(diff) => {
                let p = self.pos as i64 + diff;
                if p < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek",
                    ));
                }
                p as u64
            }
            SeekFrom::End(diff) => {
                let p = self.total_len as i64 + diff;
                if p < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek",
                    ));
                }
                p as u64
            }
        };

        let (idx, offset) = self.locate(new_pos);
        self.pos = new_pos;
        if let Some(ref mut file) = self.current_file {
            if idx == self.current_idx {
                file.seek(SeekFrom::Start(offset))?;
            } else {
                self.current_file = None;
            }
        }
        Ok(self.pos)
    }
}

// ─── Compression helpers ────────────────────────────────────────────

/// Builds the `sevenz-rust2` encoder chain for a given compression level + password.
fn build_content_methods(compression: u32, password: &str) -> Vec<EncoderConfiguration> {
    let aes: EncoderConfiguration = AesEncoderOptions::new(password.into()).into();
    if compression == 0 {
        vec![aes, EncoderMethod::COPY.into()]
    } else {
        let lzma2 = Lzma2Options::from_level(compression);
        vec![aes, lzma2.into()]
    }
}

/// Compress a directory into an encrypted 7z archive.
///
/// The archive stores the directory *contents* (not the directory itself),
/// matching `7z a archive.7z <folder>` behaviour (folder name is the top-level
/// entry inside the archive).
pub fn compress_directory(
    src: &Path,
    dest_7z: &Path,
    password: &str,
    compression: u32,
    quiet: bool,
) -> Result<(), ScchError> {
    if !src.is_dir() {
        return Err(ScchError::Validation(format!(
            "{} is not a directory",
            src.display()
        )));
    }

    if let Some(parent) = dest_7z.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut writer = ArchiveWriter::create(dest_7z)?;
    writer.set_content_methods(build_content_methods(compression, password));
    writer.set_encrypt_header(true);

    // Walk the source directory. We use the parent of `src` as the root
    // so the top-level folder name is preserved inside the archive —
    // matching the Python version's `7z a ... <folder>` behaviour.
    let root = src.parent().unwrap_or(src);

    let mut file_count = 0u64;
    let mut total_bytes = 0u64;

    for entry in walkdir::WalkDir::new(src).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|e| ScchError::Other(e.to_string()))?
            .to_string_lossy()
            .to_string();

        if rel.is_empty() {
            continue;
        }

        if path.is_dir() {
            let mut ae = ArchiveEntry::from_path(path, rel);
            ae.is_directory = true;
            writer.push_archive_entry::<&[u8]>(ae, None)?;
        } else {
            let meta = fs::metadata(path)?;
            total_bytes += meta.len();
            file_count += 1;
            let ae = ArchiveEntry::from_path(path, rel);
            let file = File::open(path)?;
            writer.push_archive_entry(ae, Some(file))?;
        }
    }

    writer.finish()?;

    if !quiet {
        let archive_size = fs::metadata(dest_7z)?.len();
        eprintln!(
            "  compressed {file_count} file(s) ({} -> {})",
            human_bytes(total_bytes),
            human_bytes(archive_size)
        );
    }

    Ok(())
}

/// Decompress an encrypted 7z archive (single file) to a destination directory.
pub fn decompress_archive(
    archive: &Path,
    dest: &Path,
    password: &str,
    _quiet: bool,
) -> Result<(), ScchError> {
    fs::create_dir_all(dest)?;
    decompress_file_with_password(archive, dest, password.into())?;
    Ok(())
}

/// Decompress a split-volume encrypted 7z archive (multiple .7z.NNN parts).
pub fn decompress_split_archive(
    parts: &[PathBuf],
    dest: &Path,
    password: &str,
    _quiet: bool,
) -> Result<(), ScchError> {
    fs::create_dir_all(dest)?;
    let reader = MultiFileReader::new(parts.to_vec())?;
    decompress_with_password(reader, dest, password.into())?;
    Ok(())
}

/// Split a single .7z file into numbered volumes (.7z.001, .7z.002, …).
/// Returns the list of part paths.
pub fn split_archive(archive: &Path, chunk_size: u64) -> Result<Vec<PathBuf>, ScchError> {
    let data = fs::read(archive)?;
    let stem = archive.display().to_string();
    let mut parts = Vec::new();
    for (num, chunk) in (1u32..).zip(data.chunks(chunk_size as usize)) {
        let part_path = PathBuf::from(format!("{stem}.{num:03}"));
        fs::write(&part_path, chunk)?;
        parts.push(part_path);
    }

    // Remove the original unsplit archive
    fs::remove_file(archive)?;

    Ok(parts)
}

/// Resolve all parts of a vault archive given any one file in the set.
/// Handles: `token.7z`, `token.7z.001`, `token.7z.sha256`, `token.7z.hmac`
pub fn resolve_parts(target: &Path) -> Result<Vec<PathBuf>, ScchError> {
    let target = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let dir = target
        .parent()
        .ok_or_else(|| ScchError::Validation("Cannot determine parent directory".to_string()))?;

    let mut base = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ScchError::Validation("Invalid filename".to_string()))?
        .to_string();

    // Strip sidecar extensions
    for ext in &[".sha256", ".hmac"] {
        if base.ends_with(ext) {
            base = base[..base.len() - ext.len()].to_string();
        }
    }

    // Extract the .7z head (strip .NNN volume suffix if present)
    let re = regex::Regex::new(r"^(.+\.7z)(\.\d{3})?$").unwrap();
    let head = re
        .captures(&base)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| {
            ScchError::Validation(
                "Not a vault archive (expected *.7z or *.7z.NNN)".to_string(),
            )
        })?;

    let part_re = regex::Regex::new(&format!(
        r"^{}(\.\d{{3}})?$",
        regex::escape(&head)
    ))
    .unwrap();

    let mut parts: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == head || part_re.is_match(&name) {
            parts.push(entry.path());
        }
    }

    parts.sort();

    if parts.is_empty() {
        return Err(ScchError::Validation("Vault archive not found".to_string()));
    }

    Ok(parts)
}

/// Returns true if the resolved parts are a split-volume archive.
pub fn is_split(parts: &[PathBuf]) -> bool {
    parts.len() > 1
        || parts
            .first()
            .is_some_and(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                regex::Regex::new(r"\.7z\.\d{3}$")
                    .unwrap()
                    .is_match(&name)
            })
}

/// Extract the encrypted filename token from the first part's filename.
/// The token is everything before `.7z` (or `.7z.001`).
pub fn extract_token(parts: &[PathBuf]) -> Result<String, ScchError> {
    let first = parts
        .first()
        .ok_or_else(|| ScchError::Validation("No archive parts".to_string()))?;
    let name = first
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ScchError::Validation("Invalid part filename".to_string()))?;

    // Strip ".7z.NNN" or ".7z"
    let re = regex::Regex::new(r"^(.+)\.7z(\.\d{3})?$").unwrap();
    let token = re
        .captures(name)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| ScchError::Validation("Cannot extract token from filename".to_string()))?;

    Ok(token)
}

/// Recursively shred (overwrite + delete) all files in a directory tree.
pub fn shred_tree(path: &Path) -> Result<(), ScchError> {
    if !path.exists() {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(path).contents_first(true) {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            // Overwrite with zeros before removing
            if let Ok(meta) = fs::metadata(p)
                && let Ok(mut f) = File::create(p)
            {
                let zeros = vec![0u8; 4096];
                let mut remaining = meta.len();
                while remaining > 0 {
                    let to_write = remaining.min(4096);
                    let _ = f.write_all(&zeros[..to_write as usize]);
                    remaining = remaining.saturating_sub(to_write);
                }
                let _ = f.flush();
            }
            fs::remove_file(p)?;
        }
    }
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

/// Validate a name for use as an output stem (no path traversal).
pub fn clean_name(name: &str) -> Result<String, ScchError> {
    let name = Path::new(name.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    if name.is_empty() || name == "." || name == ".." {
        return Err(ScchError::Validation("Invalid output name".to_string()));
    }
    Ok(name)
}

/// Human-readable byte count (e.g. "1.5 MiB").
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} PiB")
}
