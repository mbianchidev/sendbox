use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, open, openat};
use zeroize::Zeroizing;

use crate::GuestError;

pub struct OpenedFile {
    pub file: File,
    pub stat: Stat,
}

pub fn open_directory_no_symlinks(path: &Path) -> Result<OwnedFd, GuestError> {
    if !path.is_absolute() {
        return Err(GuestError::Runtime(format!(
            "secure directory path must be absolute: {}",
            path.display()
        )));
    }

    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| GuestError::io("opening filesystem root", io::Error::from(error)))?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    GuestError::io("opening secure directory component", io::Error::from(error))
                })?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(GuestError::Runtime(format!(
                    "invalid secure directory path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(directory)
}

pub fn open_relative_regular(
    root: &OwnedFd,
    relative: &Path,
    context: &'static str,
) -> Result<OpenedFile, GuestError> {
    validate_relative_path(relative)?;
    let mut components = relative.components().peekable();
    let mut directory = root
        .try_clone()
        .map_err(|error| GuestError::io(context, error))?;

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(GuestError::Artifact {
                path: relative.display().to_string(),
                detail: "path contains an invalid component".to_owned(),
            });
        };
        if components.peek().is_some() {
            directory = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| GuestError::Artifact {
                path: relative.display().to_string(),
                detail: io::Error::from(error).to_string(),
            })?;
            continue;
        }

        let descriptor = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| GuestError::Artifact {
            path: relative.display().to_string(),
            detail: io::Error::from(error).to_string(),
        })?;
        let stat = fstat(&descriptor).map_err(|error| GuestError::Artifact {
            path: relative.display().to_string(),
            detail: io::Error::from(error).to_string(),
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(GuestError::Artifact {
                path: relative.display().to_string(),
                detail: "artifact is not a regular file".to_owned(),
            });
        }
        return Ok(OpenedFile {
            file: File::from(descriptor),
            stat,
        });
    }

    Err(GuestError::Artifact {
        path: relative.display().to_string(),
        detail: "empty artifact path".to_owned(),
    })
}

pub fn read_bounded(file: &mut File, limit: usize) -> Result<Zeroizing<Vec<u8>>, GuestError> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(u64::try_from(limit + 1).expect("bounded size fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|error| GuestError::io("reading bounded file", error))?;
    if bytes.len() > limit {
        return Err(GuestError::BootstrapTooLarge(limit));
    }
    Ok(bytes)
}

pub fn validate_regular_metadata(
    stat: &Stat,
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
    single_link: bool,
    subject: &str,
) -> Result<(), GuestError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(GuestError::Bootstrap(format!(
            "{subject} is not a regular file"
        )));
    }
    #[allow(clippy::useless_conversion)] // st_mode is u16 on macOS and u32 on Linux.
    let actual_mode = u32::from(stat.st_mode & 0o7777);
    if actual_mode != expected_mode {
        return Err(GuestError::Bootstrap(format!(
            "{subject} mode is {actual_mode:#o}, expected {expected_mode:#o}"
        )));
    }
    if stat.st_uid != expected_uid || stat.st_gid != expected_gid {
        return Err(GuestError::Bootstrap(format!(
            "{subject} owner is {}:{}, expected {expected_uid}:{expected_gid}",
            stat.st_uid, stat.st_gid
        )));
    }
    if single_link && stat.st_nlink != 1 {
        return Err(GuestError::Bootstrap(format!(
            "{subject} has {} hard links, expected one",
            stat.st_nlink
        )));
    }
    Ok(())
}

pub fn validate_relative_path(path: &Path) -> Result<(), GuestError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(GuestError::Manifest(format!(
            "artifact path must be non-empty and relative: {}",
            path.display()
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(GuestError::Manifest(format!(
            "artifact path contains a forbidden component: {}",
            path.display()
        )));
    }
    Ok(())
}

pub fn leaf_name(path: &Path) -> Result<(&Path, &OsStr), GuestError> {
    let parent = path
        .parent()
        .ok_or_else(|| GuestError::Bootstrap(format!("path has no parent: {}", path.display())))?;
    let name = path.file_name().ok_or_else(|| {
        GuestError::Bootstrap(format!("path has no file name: {}", path.display()))
    })?;
    Ok((parent, name))
}

pub fn unlink_relative(
    directory: &OwnedFd,
    name: &OsStr,
    context: &'static str,
) -> Result<(), GuestError> {
    rustix::fs::unlinkat(directory, name, AtFlags::empty())
        .map_err(|error| GuestError::io(context, io::Error::from(error)))
}

#[cfg(test)]
pub(crate) fn secure_tempdir() -> tempfile::TempDir {
    let base = std::env::current_dir()
        .expect("current directory")
        .canonicalize()
        .expect("canonical test base");
    open_directory_no_symlinks(&base).expect("test base must not traverse symlinks");
    tempfile::tempdir_in(base).expect("secure temporary directory")
}
