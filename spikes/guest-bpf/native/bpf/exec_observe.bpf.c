#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16
#define FILENAME_LEN 128

struct exec_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
};

_Static_assert(sizeof(struct exec_event) == 168, "exec_event layout changed");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int observe_exec(struct trace_event_raw_sched_process_exec *context)
{
    struct exec_event *event;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u32 filename_location;
    const char *filename;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == 0)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)pid_tgid;
    event->tgid = (__u32)(pid_tgid >> 32);
    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    filename_location = context->__data_loc_filename;
    filename = (const char *)context + (filename_location & 0xffffU);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
