#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

BPF_HASH(start_time, u32, u64);
BPF_HASH(cpu_wakeups, u32, u64);
BPF_HASH(cpu_time_ns, u32, u64);
BPF_HASH(mem_usage_bytes, u32, u64);
BPF_HASH(net_rx_packets, u32, u64);
BPF_HASH(net_tx_packets, u32, u64);
BPF_HASH(disk_read_bytes, u32, u64);
BPF_HASH(disk_write_bytes, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 ts = bpf_ktime_get_ns();

    // Handle the task that is being switched out
    u64 *start_ns = start_time.lookup(&prev_pid);
    if (start_ns) {
        u64 delta = ts - *start_ns;
        u64 *total_ns = cpu_time_ns.lookup_or_try_init(&prev_pid, &delta);
        if (total_ns) {
            *total_ns += delta;
        }
        start_time.delete(&prev_pid);
    }

    // Record the start time for the task being switched in
    start_time.update(&next_pid, &ts);

    // Increment wakeup count for the task being switched in
    u64 zero = 0;
    u64 *wakeup_count = cpu_wakeups.lookup_or_try_init(&next_pid, &zero);
    if (wakeup_count) {
        *wakeup_count += 1;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
     if ((task->flags & PF_KTHREAD) == 0) {
        u32 pid = task->pid;
        u64 zero = 0;
        u64 *mem_usage = mem_usage_bytes.lookup_or_try_init(&pid, &zero);
        if (mem_usage) {
            struct mm_struct *mm = NULL;
            unsigned long total_vm = 0;
            bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
            if (mm != NULL) {
                bpf_probe_read_kernel(&total_vm, sizeof(total_vm), &mm->total_vm);
                *mem_usage = total_vm * PAGE_SIZE;
            }
        }
    }

    return 0;
}

// int sample_mem_usage(struct bpf_perf_event_data *ctx) {
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     if ((task->flags & PF_KTHREAD) == 0) {

//         u32 pid = task->pid;
//         u64 zero = 0;
//         u64 *mem_usage = mem_usage_bytes.lookup_or_try_init(&pid, &zero);
//         if (mem_usage) {
//             struct mm_struct *mm = NULL;
//             unsigned long total_vm = 0;
//             bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
//             if (mm != NULL) {
//                 bpf_probe_read_kernel(&total_vm, sizeof(total_vm), &mm->total_vm);
//                 *mem_usage = total_vm * PAGE_SIZE;
//             }
//         }
//     }
//     return 0;
// }

// Network packet monitoring
TRACEPOINT_PROBE(net, netif_receive_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 one = 1;
    u64 *rx_packets = net_rx_packets.lookup_or_try_init(&pid, &one);
    if (rx_packets) {
        *rx_packets += 1;
    }
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 one = 1;
    u64 *tx_packets = net_tx_packets.lookup_or_try_init(&pid, &one);
    if (tx_packets) {
        *tx_packets += 1;
    }
    return 0;
}

// Disk I/O monitoring
TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 bytes = args->bytes;

    char rwbs[8];
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), args->rwbs);

    // Determine if the operation is a read or write
    if (rwbs[0] == 'R') {
        u64 *read_bytes = disk_read_bytes.lookup_or_try_init(&pid, &bytes);
        if (read_bytes) {
            *read_bytes += bytes;
        }
    } else if (rwbs[0] == 'W') {
        u64 *write_bytes = disk_write_bytes.lookup_or_try_init(&pid, &bytes);
        if (write_bytes) {
            *write_bytes += bytes;
        }
    }
    return 0;
}