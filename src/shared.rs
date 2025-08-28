// use directories::ProjectDirs;
// use once_cell::sync::Lazy;
// use std::{fs, io, path::PathBuf};
use std::io;
use crate::hibp;

// static PROJECT_DIRS: Lazy<Option<ProjectDirs>> = Lazy::new(|| ProjectDirs::from("", "", "emicon"));

#[derive(Debug, thiserror::Error)]
pub enum EmiconError {
    // #[error("Could no resolve the program directories.")]
    // ProgramDirsUnavailable,
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    HibpError(#[from] hibp::HibpError),
    #[error("Slint Error: {0}")]
    SlintError(#[from] slint::PlatformError),
    #[error("JSON parsing failed: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

pub type EmiconResult<T> = std::result::Result<T, EmiconError>;

// fn project_dirs() -> Result<&'static ProjectDirs> {
//     PROJECT_DIRS
//         .as_ref()
//         .ok_or_else(|| EmiconError::ProgramDirsUnavailable)
// }

// pub fn data_directory() -> Result<PathBuf> {
//     fs::create_dir_all(project_dirs()?.data_dir())?;
//     Ok(project_dirs()?.data_dir().to_path_buf())
// }

// pub fn config_directory() -> Result<PathBuf> {
//     fs::create_dir_all(project_dirs()?.config_dir())?;
//     Ok(project_dirs()?.config_dir().to_path_buf())
// }

