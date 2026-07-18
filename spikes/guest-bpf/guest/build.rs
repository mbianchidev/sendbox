use std::env;
use std::path::PathBuf;
use std::process::{Command, Output};

fn main() {
    println!("cargo:rerun-if-changed=../native/bpf/exec_observe.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_LLVM_READELF");
    println!("cargo:rerun-if-env-changed=BPF_SYS_INCLUDE");
    println!("cargo:rerun-if-env-changed=BPF_VMLINUX_DIR");

    let arch =
        env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo did not provide target architecture");
    let target_arch = match arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("unsupported BPF target architecture: {other}"),
    };
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not provide manifest directory"),
    );
    let source = manifest_dir.join("../native/bpf/exec_observe.bpf.c");
    let vmlinux_dir = required_path("BPF_VMLINUX_DIR");
    let system_include = required_path("BPF_SYS_INCLUDE");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not provide OUT_DIR"));
    let object = out_dir.join("exec_observe.bpf.o");
    let clang = env::var("BPF_CLANG").unwrap_or_else(|_| "clang-14".to_owned());
    let readelf = env::var("BPF_LLVM_READELF").unwrap_or_else(|_| "llvm-readelf-14".to_owned());

    let output = Command::new(&clang)
        .args([
            "-target",
            "bpfel",
            "-D__BPF_TRACING__",
            &format!("-D__TARGET_ARCH_{target_arch}"),
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wconversion",
            "-Wformat=2",
            "-Wshadow",
            "-fno-stack-protector",
            "-I",
        ])
        .arg(&vmlinux_dir)
        .args(["-I"])
        .arg(&system_include)
        .args(["-I", "/usr/include", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {clang}: {error}"));
    require_success(&clang, output);

    let sections = Command::new(&readelf)
        .args(["--sections"])
        .arg(&object)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {readelf}: {error}"));
    require_success(&readelf, sections.clone());
    let section_text = String::from_utf8(sections.stdout).expect("readelf output was not UTF-8");
    for required in [".BTF", ".BTF.ext", "tracepoint/sched"] {
        assert!(
            section_text.contains(required),
            "BPF object is missing required section {required}"
        );
    }
}

fn required_path(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| panic!("{name} must be set"));
    let path = PathBuf::from(value);
    assert!(path.exists(), "{name} does not exist: {}", path.display());
    path
}

fn require_success(command: &str, output: Output) {
    if output.status.success() {
        return;
    }

    panic!(
        "{command} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
