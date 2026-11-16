use std::fmt;

#[derive(Debug)]
pub enum ScchError {
    Io(std::io::Error),
    SevenZ(sevenz_rust2::Error),
    Crypto(String),
    Validation(String),
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    Other(String),
}

impl fmt::Display for ScchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScchError::Io(e) => write!(f, "I/O error: {e}"),
            ScchError::SevenZ(e) => write!(f, "7z engine error: {e}"),
            ScchError::Crypto(msg) => write!(f, "Cryptographic error: {msg}"),
            ScchError::Validation(msg) => write!(f, "Validation error: {msg}"),
            ScchError::ChecksumMismatch { file, expected, actual } => {
                write!(
                    f,
                    "INTEGRITY FAILURE: {file} — expected checksum {expected}, got {actual}"
                )
            }
            ScchError::Other(msg) => write!(f, "Error: {msg}"),
        }
    }
}

impl std::error::Error for ScchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScchError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ScchError {
    fn from(e: std::io::Error) -> Self {
        ScchError::Io(e)
    }
}

impl From<sevenz_rust2::Error> for ScchError {
    fn from(e: sevenz_rust2::Error) -> Self {
        ScchError::SevenZ(e)
    }
}

impl From<walkdir::Error> for ScchError {
    fn from(e: walkdir::Error) -> Self {
        ScchError::Io(e.into())
    }
}
