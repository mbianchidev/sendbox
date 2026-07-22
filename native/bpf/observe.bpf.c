#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define EVENT_SCHEMA_VERSION 1
#define EVENT_KIND_EXEC 1
#define EVENT_KIND_SYSCALL 2
#define EVENT_KIND_MCP 3
#define COMM_LEN 16
#define FILENAME_LEN 128
#define MCP_CAPTURE_LEN 256

struct sendbox_event_header {
    __u16 size;
    __u8 version;
    __u8 kind;
    __u32 flags;
};

struct exec_event {
    struct sendbox_event_header header;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
};

struct syscall_event {
    struct sendbox_event_header header;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_id;
    __u32 reserved;
    __u64 arguments[6];
};

struct mcp_event {
    struct sendbox_event_header header;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u8 direction;
    __u8 transport;
    __u16 reserved;
    __u32 payload_len;
    __u32 captured_len;
    __u8 payload[MCP_CAPTURE_LEN];
    __u32 reserved_tail;
};

_Static_assert(sizeof(struct sendbox_event_header) == 8, "event header layout changed");
_Static_assert(sizeof(struct exec_event) == 176, "exec_event layout changed");
_Static_assert(sizeof(struct syscall_event) == 88, "syscall_event layout changed");
_Static_assert(sizeof(struct mcp_event) == 296, "mcp_event layout changed");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} losses SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} scope SEC(".maps");

static __always_inline bool in_scope(void)
{
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&scope, &key);

    return target != 0 && *target != 0 && bpf_get_current_cgroup_id() == *target;
}

static __always_inline void account_reserve_failure(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&losses, &key);

    if (count != 0)
        __sync_fetch_and_add(count, 1);
}

static __always_inline void fill_identity(
    __u32 *pid,
    __u32 *tgid,
    __u32 *uid,
    __u32 *gid)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    *pid = (__u32)pid_tgid;
    *tgid = (__u32)(pid_tgid >> 32);
    *uid = (__u32)uid_gid;
    *gid = (__u32)(uid_gid >> 32);
}

SEC("tracepoint/sched/sched_process_exec")
int observe_exec(struct trace_event_raw_sched_process_exec *context)
{
    struct exec_event *event;
    __u32 filename_location;
    const char *filename;

    if (!in_scope())
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == 0) {
        account_reserve_failure();
        return 0;
    }

    event->header.size = sizeof(*event);
    event->header.version = EVENT_SCHEMA_VERSION;
    event->header.kind = EVENT_KIND_EXEC;
    event->header.flags = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    fill_identity(&event->pid, &event->tgid, &event->uid, &event->gid);
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    filename_location = context->__data_loc_filename;
    filename = (const char *)context + (filename_location & 0xffffU);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int observe_sys_enter(struct trace_event_raw_sys_enter *context)
{
    struct syscall_event *event;

    if (!in_scope())
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == 0) {
        account_reserve_failure();
        return 0;
    }

    event->header.size = sizeof(*event);
    event->header.version = EVENT_SCHEMA_VERSION;
    event->header.kind = EVENT_KIND_SYSCALL;
    event->header.flags = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    fill_identity(&event->pid, &event->tgid, &event->uid, &event->gid);
    event->syscall_id = (__u32)context->id;
    event->reserved = 0;
    __builtin_memcpy(event->arguments, context->args, sizeof(event->arguments));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
