// probes/exec_probe.c
// eBPF C probe loaded at runtime by detector.py via BCC.
// Attaches to the sched_process_exec tracepoint.
// Extracts: PID, PPID, comm (parent process name), filename (child binary path), UID.
// Pushes a structured event into the perf buffer for user-space consumption.
//
// Decision rationale (Issue #7):
// We use the stable kernel tracepoint `sched_process_exec` rather than kprobes.
// Kprobes attach to kernel function symbols (e.g., __x64_sys_execve or do_execve)
// which can vary or change internal signatures across kernel versions and distributions.
// In contrast, tracepoints provide a stable ABI contract that persists across kernel updates.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event struct definition (Issue #21):
// - pid: Thread group ID / user-space PID of executing child process.
// - ppid: Parent process ID obtained from task_struct->real_parent->tgid.
// - uid: User ID of process owner.
// - comm: Parent process name. Size 16 corresponds to TASK_COMM_LEN in the Linux kernel.
// - filename: Executable path. 256 bytes provides adequate headroom for typical binary
//   paths while maintaining bounded memory in the perf buffer. Paths exceeding 255
//   characters are truncated safely with a null terminator.
struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
        bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), parent->comm);
    }

    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), args->filename);

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}
