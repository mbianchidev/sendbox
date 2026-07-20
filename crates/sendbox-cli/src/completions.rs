use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use sendbox_config::{AtomicWriteMode, atomic_write_file};

const COMPLETION_FILE_MODE: u32 = 0o644;
const COMPLETION_DIRECTORY_MODE: u32 = 0o755;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionShell {
    pub(crate) fn detect() -> Result<Self, String> {
        let shell = env::var_os("SHELL")
            .ok_or_else(|| "SHELL is not set; pass --shell bash|zsh|fish".to_owned())?;
        let name = Path::new(&shell)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        match name {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            _ => Err(format!(
                "unsupported shell '{}'; pass --shell bash|zsh|fish",
                shell.to_string_lossy()
            )),
        }
    }

    pub(crate) fn generate(self) -> Vec<u8> {
        let mut command = <crate::Cli as clap::CommandFactory>::command();
        let mut output = Vec::new();
        clap_complete::generate(self.generator(), &mut command, "sendbox", &mut output);
        output
    }

    pub(crate) fn install(self) -> io::Result<PathBuf> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        self.install_in(&home)
    }

    fn install_in(self, home: &Path) -> io::Result<PathBuf> {
        let path = self.install_path(home);
        let parent = path.parent().expect("completion path always has a parent");
        fs::create_dir_all(parent)?;
        set_directory_mode(parent, COMPLETION_DIRECTORY_MODE)?;
        atomic_write_file(
            &path,
            &self.generate(),
            COMPLETION_FILE_MODE,
            AtomicWriteMode::Replace,
        )?;
        Ok(path)
    }

    fn install_path(self, home: &Path) -> PathBuf {
        match self {
            Self::Bash => home.join(".local/share/bash-completion/completions/sendbox"),
            Self::Zsh => home.join(".zsh/completions/_sendbox"),
            Self::Fish => home.join(".config/fish/completions/sendbox.fish"),
        }
    }

    fn generator(self) -> clap_complete::Shell {
        match self {
            Self::Bash => clap_complete::Shell::Bash,
            Self::Zsh => clap_complete::Shell::Zsh,
            Self::Fish => clap_complete::Shell::Fish,
        }
    }
}

impl fmt::Display for CompletionShell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        })
    }
}

#[cfg(unix)]
fn set_directory_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn stable_install_paths_match_supported_shell_conventions() {
        let home = Path::new("/home/example");
        assert_eq!(
            CompletionShell::Bash.install_path(home),
            home.join(".local/share/bash-completion/completions/sendbox")
        );
        assert_eq!(
            CompletionShell::Zsh.install_path(home),
            home.join(".zsh/completions/_sendbox")
        );
        assert_eq!(
            CompletionShell::Fish.install_path(home),
            home.join(".config/fish/completions/sendbox.fish")
        );
    }

    #[cfg(unix)]
    #[test]
    fn installs_completion_with_stable_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempdir().unwrap();
        let path = CompletionShell::Zsh.install_in(home.path()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}
