#![forbid(unsafe_code)]

use std::{
    env,
    io::{self, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let mode = arguments.next().ok_or_else(|| "missing mode".to_owned())?;
    match mode.as_str() {
        "saturate" => {
            let chunks = parse_usize(arguments.next(), "chunks")?;
            let chunk_bytes = parse_usize(arguments.next(), "chunk bytes")?;
            let stdout_thread =
                thread::spawn(move || write_repeated(io::stdout(), b'O', chunks, chunk_bytes));
            let stderr_thread =
                thread::spawn(move || write_repeated(io::stderr(), b'E', chunks, chunk_bytes));
            stdout_thread
                .join()
                .map_err(|_| "stdout writer panicked".to_owned())??;
            stderr_thread
                .join()
                .map_err(|_| "stderr writer panicked".to_owned())??;
        }
        "sleep" => {
            let milliseconds = parse_u64(arguments.next(), "milliseconds")?;
            thread::sleep(Duration::from_millis(milliseconds));
        }
        "exit" => {
            let code = arguments
                .next()
                .ok_or_else(|| "missing exit code".to_owned())?
                .parse::<i32>()
                .map_err(|error| format!("invalid exit code: {error}"))?;
            std::process::exit(code);
        }
        "echo-env" => {
            let key = arguments
                .next()
                .ok_or_else(|| "missing environment key".to_owned())?;
            println!(
                "{}",
                env::var(key).unwrap_or_else(|_| "<missing>".to_owned())
            );
        }
        "cwd" => {
            println!(
                "{}",
                env::current_dir()
                    .map_err(|error| error.to_string())?
                    .display()
            );
        }
        "spawn-child" => {
            let milliseconds = parse_u64(arguments.next(), "milliseconds")?;
            let child = Command::new(env::current_exe().map_err(|error| error.to_string())?)
                .arg("sleep")
                .arg(milliseconds.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| error.to_string())?;
            println!("{}", child.id());
            io::stdout().flush().map_err(|error| error.to_string())?;
            thread::sleep(Duration::from_millis(milliseconds));
        }
        other => return Err(format!("unknown mode `{other}`")),
    }
    Ok(())
}

fn write_repeated(
    mut writer: impl Write,
    byte: u8,
    chunks: usize,
    chunk_bytes: usize,
) -> Result<(), String> {
    let chunk = vec![byte; chunk_bytes];
    for _ in 0..chunks {
        writer
            .write_all(&chunk)
            .map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn parse_usize(value: Option<String>, name: &str) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn parse_u64(value: Option<String>, name: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}
