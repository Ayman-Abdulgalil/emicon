// use directories::ProjectDirs;
// use once_cell::sync::Lazy;
// use std::{fs, io, path::PathBuf};
use std::io;
use thiserror::Error;

// static PROJECT_DIRS: Lazy<Option<ProjectDirs>> = Lazy::new(|| ProjectDirs::from("", "", "emicon"));

#[derive(Error, Debug)]
pub enum HibpError {
    #[error("Email not found in any breaches")]
    NotFound,
    #[error("Rate limited - too many requests")]
    RateLimit,
    #[error("Unauthorized - invalid API key")]
    Unauthorized,
    #[error("Forbidden - request forbidden")]
    Forbidden,
    #[error("Bad request - invalid email format")]
    BadRequest,
    #[error("Service unavailable")]
    ServiceUnavailable,
    #[error("Unknown error: {status} - {message}")]
    Unknown { status: u16, message: String },
}

/// Application-wide error type.
#[derive(Debug, Error)]
pub enum EmiconError {
    // #[error("Could no resolve the program directories.")]
    // ProgramDirsUnavailable,
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    HibpError(#[from] HibpError),
    #[error("Slint Error")]
    SlintError(#[from] slint::PlatformError),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// Application-wide result type.
pub type Result<T> = std::result::Result<T, EmiconError>;

// fn project_dirs() -> Result<&'static ProjectDirs> {
//     PROJECT_DIRS
//         .as_ref()
//         .ok_or_else(|| EmiconError::ProgramDirsUnavailable)
// }

// /// Returns the standard local data directory for the app, as specified in the
// /// **directories** crate.
// ///
// /// Defaults to:
// /// - **Linux:** `~/.local/share/emicon`
// /// - **Windows:** `%LOCALAPPDATA%\emicon`
// /// - **macOS:** `~/Library/Application Support/emicon`
// ///
// /// If not found, path is created.
// pub fn data_directory() -> Result<PathBuf> {
//     fs::create_dir_all(project_dirs()?.data_dir())?;
//     Ok(project_dirs()?.data_dir().to_path_buf())
// }

// /// Returns the standard local config directory for the app, as specified in the
// /// **directories** crate.
// ///
// /// Defaults to:
// /// - **Linux:** `~/.config/emicon`
// /// - **Windows:** `%APPDATA%\emicon`
// /// - **macOS:** `~/Library/Preferences/emicon`
// ///
// /// If not found, path is created.
// pub fn config_directory() -> Result<PathBuf> {
//     fs::create_dir_all(project_dirs()?.config_dir())?;
//     Ok(project_dirs()?.config_dir().to_path_buf())
// }

