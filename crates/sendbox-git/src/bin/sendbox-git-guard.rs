use std::{env, path::Path};

use sendbox_git::{GuardError, execute_guarded_git};

const EXIT_DENIED: i32 = 128;

fn main() {
    if let Err(error) = run() {
        eprintln!("[sendbox-git-guard] {error}");
        std::process::exit(EXIT_DENIED);
    }
}

fn run() -> Result<(), GuardError> {
    let mut arguments = env::args().skip(1);
    let policy_path = required_flag(&mut arguments, "--policy")?;
    let git_path = required_flag(&mut arguments, "--git")?;
    if arguments.next().as_deref() != Some("--") {
        return Err(GuardError::InvalidInvocation(
            "expected `--` before Git arguments".to_owned(),
        ));
    }
    let git_arguments = arguments.collect::<Vec<_>>();
    execute_guarded_git(
        Path::new(&policy_path),
        Path::new(&git_path),
        &git_arguments,
    )
}

fn required_flag(
    arguments: &mut impl Iterator<Item = String>,
    expected: &str,
) -> Result<String, GuardError> {
    let flag = arguments.next().ok_or_else(|| {
        GuardError::InvalidInvocation(format!("required option `{expected}` is missing"))
    })?;
    if flag != expected {
        return Err(GuardError::InvalidInvocation(format!(
            "expected option `{expected}`"
        )));
    }
    arguments.next().ok_or_else(|| {
        GuardError::InvalidInvocation(format!("option `{expected}` is missing its value"))
    })
}
