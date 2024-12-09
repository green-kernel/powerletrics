#pragma GCC diagnostic ignored "-Wduplicate-decl-specifier"

//#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

BPF_HASH(start_time, u32, u64);
BPF_HASH(cpu_wakeups, u32, u64);
BPF_HASH(cpu_time_ns, u32, u64);
BPF_HASH(ebpf_time_ns, u32, u64);

BPF_HASH(mem_usage_bytes, u32, u64);
BPF_HASH(net_rx_packets, u32, u64);
BPF_HASH(net_tx_packets, u32, u64);
BPF_HASH(disk_read_bytes, u32, u64);
BPF_HASH(disk_write_bytes, u32, u64);

// Getting idle time needs to be indexed by cpu
BPF_HASH(idle_start_time_ns, u32, u64);
BPF_HASH(idle_time_ns, u32, u64);

// We save the comm of a pid here
struct pid_comm_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    bool is_thread;
};

BPF_TABLE("lru_hash", u32, struct pid_comm_t, pid_comm_map, __COMM_LENGTH__);

TRACEPOINT_PROBE(power, cpu_idle) {
    u32 cpu = args->cpu_id;
    int state = args->state;
    u64 ts = bpf_ktime_get_ns();

    if (state >= 0) {
        // CPU is entering idle state
        idle_start_time_ns.update(&cpu, &ts);
    } else if (state == -1) {
        // CPU is exiting idle state
        u64 *start_ns = idle_start_time_ns.lookup(&cpu);
        if (start_ns) {
            u64 delta = ts - *start_ns;
            u64 zero = 0;
            u64 *total_ns = idle_time_ns.lookup_or_try_init(&cpu, &zero);
            if (total_ns) {
                *total_ns += delta;
            }
            idle_start_time_ns.delete(&cpu);
        }
    }
    return 0;
}


TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u64 zero = 0;

    char prev_comm[TASK_COMM_LEN];
    char next_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(prev_comm, sizeof(prev_comm), args->prev_comm);
    bpf_probe_read_kernel_str(next_comm, sizeof(next_comm), args->next_comm);
    // Store the comm for the pids
    //struct pid_comm_t *existing_entry;


    // Get the task_struct of the currently executing task (which is now next_pid)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 tgid = 0;
    u32 pid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &task->tgid);
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);

    bool is_thread_next = (pid != tgid);

    // existing_entry = pid_comm_map.lookup(&next_pid);
    // if (!existing_entry) {
        struct pid_comm_t pid_comm = {};
        pid_comm.pid = next_pid;
        __builtin_memcpy(&pid_comm.comm, &next_comm, sizeof(next_comm));
        pid_comm.is_thread = is_thread_next;
        pid_comm_map.update(&next_pid, &pid_comm);
    // }

    // existing_entry = pid_comm_map.lookup(&prev_pid);
    // if (!existing_entry) {
        struct pid_comm_t prev_pid_comm = {};
        prev_pid_comm.pid = prev_pid;
        __builtin_memcpy(&prev_pid_comm.comm, &prev_comm, sizeof(prev_comm));
        struct pid_comm_t *prev_entry = pid_comm_map.lookup(&prev_pid);
        if (prev_entry) {
            prev_pid_comm.is_thread = prev_entry->is_thread;
        } else {
            prev_pid_comm.is_thread = false;
        }
        pid_comm_map.update(&prev_pid, &prev_pid_comm);
    // }


    // We used to handle the idle time with pid 0 but having an own tracepoint was more reliable. Keeping this for referece
    if (prev_pid == 0) {
    //     // cpu_time_ns.lookup_or_try_init(&prev_pid, &zero);
    //     // u64 *start_ns = idle_start_time_ns.lookup(&cpu);
    //     // if (start_ns) {
    //     //     u64 delta = ts - *start_ns;
    //     //     u64 *total_ns = idle_time_ns.lookup_or_try_init(&cpu, &zero);
    //     //     if (total_ns) {
    //     //         *total_ns += delta;
    //     //     }
    //     //     idle_start_time_ns.delete(&cpu);
    //     // }
    }else{
        // Handle the task that is being switched out
        u64 *start_ns = start_time.lookup(&prev_pid);
        if (start_ns) {
            u64 delta = ts - *start_ns;
            u64 *total_ns = cpu_time_ns.lookup_or_try_init(&prev_pid, &delta);
            if (total_ns) {
                *total_ns += delta;
            }
            start_time.delete(&prev_pid);
        } else {
            u64 *total_ns = cpu_time_ns.lookup_or_try_init(&prev_pid, &zero);
        }
    }

    // Handle the idle task being scheduled in
    if (next_pid == 0) {
        // idle_start_time_ns.update(&cpu, &ts);
    }else{
        //Record the start time for the task being switched in
        start_time.update(&next_pid, &ts);
    }

    if(next_pid != 0){
        // Increment wakeup count for the task being switched in
        u64 *wakeup_count = cpu_wakeups.lookup_or_try_init(&next_pid, &zero);
        if (wakeup_count) {
            *wakeup_count += 1;
        }
    }

     if ((task->flags & PF_KTHREAD) == 0) {
        u32 pid = task->pid;
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

    if (prev_pid != 0) {
        u64 end_ts = bpf_ktime_get_ns();
        u64 duration = end_ts - ts;

        u64 *total_ns = ebpf_time_ns.lookup_or_try_init(&prev_pid, &duration);
        if (total_ns) {
            *total_ns += duration;
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