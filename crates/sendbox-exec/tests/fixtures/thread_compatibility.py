import ctypes
import errno
import json
import os
import platform
import signal


libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
failures = []
if hasattr(libc, "gnu_get_libc_version"):
    libc.gnu_get_libc_version.restype = ctypes.c_char_p
    print("GLIBC_VERSION=" + libc.gnu_get_libc_version().decode("ascii"), flush=True)


def expect(condition, label):
    if not condition:
        failures.append(label)


def check_clone3(arguments, size, label):
    ctypes.set_errno(0)
    result = libc.syscall(435, arguments, ctypes.c_size_t(size))
    error = ctypes.get_errno()
    if result == 0:
        os._exit(95)
    if result > 0:
        os.waitpid(result, 0)
    expect(result == -1 and error == errno.ENOSYS, f"{label}: {result}, errno={error}")


check_clone3(ctypes.c_void_p(), 0, "clone3 null")
callback_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
completed = []


@callback_type
def callback(_):
    completed.append("thread")
    return None


libc.pthread_create.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_void_p,
    callback_type,
    ctypes.c_void_p,
]
libc.pthread_create.restype = ctypes.c_int
libc.pthread_join.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
libc.pthread_join.restype = ctypes.c_int
thread = ctypes.c_ulong()
created = libc.pthread_create(ctypes.byref(thread), None, callback, None)
print(f"pthread_create={created}", flush=True)
expect(created == 0, f"pthread_create={created}")
if created == 0:
    joined = libc.pthread_join(thread, None)
    expect(joined == 0 and completed == ["thread"], f"pthread_join={joined}, callback={completed}")


class CloneArgs(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in [
            "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
            "stack_size", "tls", "set_tid", "set_tid_size", "cgroup",
        ]
    ]


namespace_flags = [
    0x00020000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000,
]
for flag in [0, *namespace_flags, 0x80, 0x8000, 0x200001000]:
    arguments = CloneArgs(flags=flag, exit_signal=signal.SIGCHLD)
    check_clone3(ctypes.byref(arguments), ctypes.sizeof(arguments), f"clone3 flags={flag:#x}")

clone_number = {"x86_64": 56, "aarch64": 220}[platform.machine()]
for flag in namespace_flags:
    ctypes.set_errno(0)
    result = libc.syscall(
        clone_number, ctypes.c_ulong(flag | signal.SIGCHLD),
        ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(),
    )
    error = ctypes.get_errno()
    if result == 0:
        os._exit(96)
    if result > 0:
        os.waitpid(result, 0)
    expect(result == -1 and error == errno.EPERM, f"clone namespace={flag:#x}: {result}, errno={error}")

for name, result_type, arguments in [
    ("unshare", ctypes.c_int, [0x10000000]),
    ("setns", ctypes.c_int, [-1, 0]),
    ("ptrace", ctypes.c_long, [0, 0, None, None]),
    ("process_vm_readv", ctypes.c_ssize_t, [0, None, 0, None, 0, 0]),
    ("process_vm_writev", ctypes.c_ssize_t, [0, None, 0, None, 0, 0]),
    ("mount", ctypes.c_int, [None, b"/", None, 0, None]),
    ("memfd_create", ctypes.c_int, [b"generated-denied-probe", 0]),
]:
    operation = getattr(libc, name)
    operation.restype = result_type
    ctypes.set_errno(0)
    result = operation(*arguments)
    error = ctypes.get_errno()
    expect(result == -1 and error == errno.EPERM, f"{name}: {result}, errno={error}")

with open("/proc/self/status", encoding="ascii") as status_file:
    status = dict(
        line.rstrip().split(":", 1)
        for line in status_file
        if line.startswith(("Uid:", "NoNewPrivs:", "Seccomp:", "CapEff:"))
    )
expect(status["NoNewPrivs"].strip() == "1", "NNP must remain enabled")
expect(status["Seccomp"].strip() == "2", "seccomp must remain enabled")
print("status=" + json.dumps(status), flush=True)
if failures:
    raise AssertionError("; ".join(failures))
print("GENERATED_THREADS_AND_DENIALS_READY", flush=True)
