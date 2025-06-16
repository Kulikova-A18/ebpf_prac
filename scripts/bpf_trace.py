from bcc import BPF

program = """
#include <uapi/linux/ptrace.h>

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    char fname[256];
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);
    bpf_trace_printk("EXEC: %s\\n", fname);
    return 0;
}

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    char fname[256];
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);
    bpf_trace_printk("OPEN: %s\\n", fname);
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")

print("Tracing execve and openat... Ctrl-C to quit.\n")

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"[PID {pid}] {msg}")
    except KeyboardInterrupt:
        break
