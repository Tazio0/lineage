# probes/exec_probe.c
# eBPF C probe loaded at runtime by detector.py via BCC.
# Responsibilities:
#   - Attach to the execve tracepoint (sys_enter_execve or sched_process_exec)
#   - Extract: PID, PPID, comm (parent), filename (child), UID
#   - Push a struct containing that data into the perf buffer
#
# NOTE: This file is compiled and loaded at runtime by BCC — not pre-compiled.
# It must stay small and restricted (no loops, no standard C library calls).
