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

// Getting idle time needs to be indexed by cpu
BPF_HASH(idle_start_time_ns, u32, u64);
BPF_HASH(idle_time_ns, u32, u64);

// We save the comm of a pid here
struct pid_comm_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(pid_comm_map, u32, struct pid_comm_t);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();

    // TASK_COMM_LEN +1 because of \0 ?
    // https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#6-bpf_get_current_comm
    char prev_comm[TASK_COMM_LEN];
    char next_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel(&prev_comm, sizeof(prev_comm), args->prev_comm);
    bpf_probe_read_kernel(&next_comm, sizeof(next_comm), args->next_comm);

    // Store the comm for the pids
    struct pid_comm_t pid_comm = {};
    pid_comm.pid = next_pid;
    __builtin_memcpy(&pid_comm.comm, &next_comm, sizeof(next_comm));
    pid_comm_map.update(&next_pid, &pid_comm);

    struct pid_comm_t prev_pid_comm = {};
    prev_pid_comm.pid = prev_pid;
    __builtin_memcpy(&prev_pid_comm.comm, &prev_comm, sizeof(prev_comm));
    pid_comm_map.update(&prev_pid, &prev_pid_comm);

    // Handle the idle task being scheduled out
    if (prev_pid == 0) {
        // Idle task is being scheduled out
        // For a lookup in the hash map, do I really have to pass the address of the int? Really? Not the value itself?
        // https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#19-maplookup
        u64 *start_ns = idle_start_time_ns.lookup(&cpu);
        // what happens if start_ns is 0? not better compare with NULL ?
        // true, but start_ns shouldn't be 0. But you could make it more explicit. As lookup returns NULL if the key is not found
        if (start_ns) {
            u64 delta = ts - *start_ns;
            u64 *total_ns = idle_time_ns.lookup(&cpu);
            // what happens if total_ns is 0? This should be more likely than start_ns not better compare with NULL ?
            if (total_ns) {
                *total_ns += delta;
                // missing update command? should it not be idle_time_ns.update(&cpu, total_ns);
                // I update the pointed to value. So it should update in the map
            } else {
                // if you store the addresses and not the values, why are these u64?
                // Becaue the map stores the acutal value not the pointer
                idle_time_ns.update(&cpu, &delta);
                
            }
            idle_start_time_ns.delete(&cpu);
        }

        // missing return statement? Why continue here?
        // if prev_pid = 0 can it also be that next_pid = ?
        // the event takes place per CPU, right? So I guess it cannot be ...
        // But I want to look at the next task?
        
    }

    // Handle the idle task being scheduled in
    if (next_pid == 0) {
        // Idle task is being scheduled in
        idle_start_time_ns.update(&cpu, &ts);
    }


    // Handle the task that is being switched out
    u64 *start_ns = start_time.lookup(&prev_pid);
    // what happens if start_ns is 0? not better compare with NULL ?
    if (start_ns) {
        u64 delta = ts - *start_ns;
        // why do you use a different command here lookup => lookup_or_try_init ?
        // Because the value can not exist here
        u64 *total_ns = cpu_time_ns.lookup_or_try_init(&prev_pid, &delta);
        if (total_ns) {
            *total_ns += delta;
            // do you not need to write total_ns somewhere?
            // It is saved by the pointer
        }
        start_time.delete(&prev_pid);
    } else {
        u64 zero = 0;
        u64 *total_ns = cpu_time_ns.lookup_or_try_init(&prev_pid, &zero);
        // do you not need to write total_ns somewhere?
    }


    // Record the start time for the task being switched in
    // This call is relevant for including or excluding the overhead of this eBPF script and is somehow in nowhere land ... Neither as early as possible, nor as late as possible. Where is it placed best? Does the event happen AFTER being scheduled on the CPU or BEFORE. In the former case I would argue to push this call to the end of the function. In the latter I would push it more to the start.
    // True, I just wanted things that belong togehter to be at the same place in the code
    start_time.update(&next_pid, &ts);

    // Increment wakeup count for the task being switched in
    // is that really all the wakeups? When a process is assigned to a CPU and has I/O wait it is not scheduled out, but still can have wakeups happening from I/O being available. Can we have a validation script for eBPF and perf_events that compares the wakeups?
    // you could also compare with sched:sched_wakeup
    u64 zero = 0;
    u64 *wakeup_count = cpu_wakeups.lookup_or_try_init(&next_pid, &zero);
    if (wakeup_count) {
        *wakeup_count += 1;
    }

    // what is coming out of bpf_get_current_task? A void pointer? suprising that you have to cast here
    // https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-bpf_get_current_task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
     if ((task->flags & PF_KTHREAD) == 0) { // what does this line mean?
         // It checks if this is a kernel thread
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
// can you document the event netif_receive_skb and why you chose this over other possible events?
TRACEPOINT_PROBE(net, netif_receive_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32; // what does this right shift do exactly?
    u64 one = 1; // why do you supply one here instead of zero in the sched Tracepoint? Is this tracepoint called for EVERY packet?
    u64 *rx_packets = net_rx_packets.lookup_or_try_init(&pid, &one);
    if (rx_packets) {
        *rx_packets += 1;
    }
    return 0;
}

// can you document the event net_dev_queue and why you chose this over other possible events?
TRACEPOINT_PROBE(net, net_dev_queue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;  // what does this right shift do exactly?
    u64 one = 1; // why do you supply one here instead of zero in the sched Tracepoint? Is this tracepoint called for EVERY packet?
    u64 *tx_packets = net_tx_packets.lookup_or_try_init(&pid, &one);
    if (tx_packets) {
        *tx_packets += 1;
    }
    return 0;
}

// Disk I/O monitoring
// can you document the event block_rq_issue and why you chose this over other possible events?
TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 bytes = args->bytes;

    char rwbs[8];
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), args->rwbs);

    // Determine if the operation is a read or write
    // Are we ignoring other types like flush and sync? Or do they also trigger a write?
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
