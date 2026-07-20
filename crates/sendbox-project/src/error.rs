use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("project path does not exist or is not a directory: {0}")]
    InvalidProjectRoot(PathBuf),
    #[error("could not access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid JSONC in {path}: {message}")]
    InvalidJsonc { path: PathBuf, message: String },
    #[error("devcontainer output must remain inside the project: {0}")]
    OutputOutsideProject(PathBuf),
    #[error("refusing to write devcontainer through a symlink: {0}")]
    SymlinkOutput(PathBuf),
    #[error("devcontainer root must be a JSON object")]
    InvalidDevContainerRoot,
    #[error("refinement provider {provider} failed: {message}")]
    Refinement { provider: String, message: String },
}

impl ProjectError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProjectError>;
