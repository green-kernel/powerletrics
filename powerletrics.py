#!/usr/bin/env python3
import os
import argparse
import time
import sys
import configparser
import datetime

from bcc import BPF, PerfType, PerfSWConfig

parser = argparse.ArgumentParser(description='System performance and energy metrics tool')
parser.add_argument('-i', '--sample-rate', type=int, default=5000,
                    help='Sample every N ms [default: 5000ms]')
parser.add_argument('-n', '--sample-count', type=int, default=0,
                    help='Obtain N periodic samples (0=infinite) [default: 0]')
parser.add_argument('-o', '--output-file', type=str,
                    help='Output to file instead of stdout')
parser.add_argument('-r', '--order', type=str, choices=['pid', 'wakeups', 'cputime', 'composite'], default='composite',
                    help='Order process list using specified method [default: composite]')
parser.add_argument('-A', '--show-all', action='store_true',
                    help='Enables all samplers and displays all the available information for each sampler.')
parser.add_argument('--show-process-energy', action='store_true',
                    help='''Show per-process energy impact number. This number is a rough
                            proxy for the total energy the process uses, including CPU,
                            disk io and networking. The weighting of each is platform
                            specific. Enabling this implicitly enables sampling of all the
                            above per-process statistics.''')
parser.add_argument('--show-process-io', action='store_true',
                    help='Show per-process io information')
parser.add_argument('--show-process-netstats', action='store_true',
                    help='Show per-process network information')
parser.add_argument('--format', type=str, choices=['text', 'plist'], default='text',
                    help='Display data in specified format [default: text]')
parser.add_argument('--ebpf-memory', action='store_true',
                    help='Enable eBPF memory sampling')
parser.add_argument('--show-command-line', action='store_true',
                    help='Shows the full command line arguments')
parser.add_argument('-f', '--flush', action='store_true',
                    help='Flushes after print')


args = parser.parse_args()

if args.output_file:
    sys.stdout = open(args.output_file, 'w')

with open("ebpf.c", 'r') as f:
    bpf_program = f.read()

config = configparser.ConfigParser()
config.read('weights.conf')

# Weights for each component
CPU_WEIGHT = float(config['Weights'].get('CPU_WEIGHT', 0.6))
WAKEUP_WEIGHT = float(config['Weights'].get('WAKEUP_WEIGHT', 0.2))
DISK_WEIGHT = float(config['Weights'].get('DISK_WEIGHT', 0.1))
NETWORK_WEIGHT = float(config['Weights'].get('NETWORK_WEIGHT', 0.1))
MEMORY_WEIGHT = float(config['Weights'].get('MEMORY_WEIGHT', 0.1))

num_cpus = os.cpu_count()

b = BPF(text=bpf_program)

class Data:
    def __init__(self):
        self.pid = 0
        self.comm = ""
        self.cmdline = ""
        self.cpu_time_ns = 0
        self.cpu_wakeups = 0
        self.memory_usage = 0
        self.memory_usage_mb = 0
        self.ebpf_memory_usage = 0
        self.ebpf_memory_usage_mb = 0
        self.net_rx_packets = 0
        self.net_tx_packets = 0
        self.disk_read_bytes = 0
        self.disk_write_bytes = 0
        self.energy_impact=0
        self.is_kernel_thread = False

# Monitoring loop
try:
    sample_interval_sec = args.sample_rate / 1000  # Convert ms to seconds
    interval_ns = sample_interval_sec * 1e9  # Convert to nanoseconds
    sample_count = args.sample_count
    current_sample = 0
    page_size = os.sysconf('SC_PAGE_SIZE')

    # Print header
    if not args.output_file:
        print("Starting powermetrics monitoring. Press Ctrl+C to stop.")

    while True:
        start_loop_time = datetime.datetime.now()
        time.sleep(sample_interval_sec)

        # Retrieve data from eBPF maps
        cpu_times = b.get_table("cpu_time_ns")
        wakeups = b.get_table("cpu_wakeups")
        rx_packets = b.get_table("net_rx_packets")
        tx_packets = b.get_table("net_tx_packets")
        disk_reads = b.get_table("disk_read_bytes")
        disk_writes = b.get_table("disk_write_bytes")

        data_list = []

        for pid_key in cpu_times.keys():
            is_kernel_thread = False

            pid = pid_key.value
            data = Data()
            data.pid = pid
            data.cpu_time_ns = cpu_times[pid_key].value
            data.cpu_wakeups = wakeups[pid_key].value if pid_key in wakeups else 0
            data.net_rx_packets = rx_packets[pid_key].value if pid_key in rx_packets else 0
            data.net_tx_packets = tx_packets[pid_key].value if pid_key in tx_packets else 0
            data.disk_read_bytes = disk_reads[pid_key].value if pid_key in disk_reads else 0
            data.disk_write_bytes = disk_writes[pid_key].value if pid_key in disk_writes else 0

            # We currently keep both implementations to debug the difference
            if args.ebpf_memory:
                ebpf_mem_usages = b.get_table("mem_usage_bytes")
                data.ebpf_memory_usage = ebpf_mem_usages[pid_key].value if pid_key in ebpf_mem_usages else 0
                data.ebpf_memory_usage_mb = data.ebpf_memory_usage / (1024 * 1024)

            try:
                with open(f"/proc/{data.pid}/cmdline", 'rb') as f:
                    data.cmdline = f.read().replace(b'\x00', b' ').strip().decode('utf-8', 'replace')
                    if data.cmdline == '':
                        data.is_kernel_thread = True
            except:
                data.cmdline = "<unknown>"

            try:
                with open(f"/proc/{data.pid}/comm", 'rb') as j:
                    data.comm = j.read().replace(b'\x00', b' ').strip().decode('utf-8', 'replace')
            except:
                data.comm = "<unknown>"

            if not data.is_kernel_thread:
                try:
                    # We don't get the memory through ebpf in the default case as there is no way to iterate over all
                    # processes in eBPF for security reasons.
                    # If you want to still use eBPD you can enable it with --ebpf-memory.
                    with open(f"/proc/{data.pid}/statm", 'r') as f:
                        statm = f.readline().split()
                        if len(statm) >= 2:
                            total_pages = int(statm[0])
                            data.memory_usage = total_pages * page_size
                            data.memory_usage_mb = data.memory_usage / (1024 * 1024)

                except:
                    data.memory_usage = 0  # Process might have exited
            else:
                # Kernel threads don't have user space memory
                data.memory_usage = 0

            data.cpu_utilization = (data.cpu_time_ns / (interval_ns * num_cpus)) * 100

            total_disk_io = data.disk_read_bytes + data.disk_write_bytes
            total_network_packets = data.net_rx_packets + data.net_tx_packets

            data.energy_impact = (CPU_WEIGHT * data.cpu_utilization) + \
                            (WAKEUP_WEIGHT * data.cpu_wakeups) + \
                            (DISK_WEIGHT * total_disk_io / 1024) + \
                            (NETWORK_WEIGHT * total_network_packets) + \
                            (MEMORY_WEIGHT * data.memory_usage_mb)


            data_list.append(data)

        # Sort data based on the selected order
        if args.order == 'pid':
            data_list.sort(key=lambda x: x.pid)
        elif args.order == 'wakeups':
            data_list.sort(key=lambda x: x.cpu_wakeups, reverse=True)
        elif args.order == 'cputime':
            data_list.sort(key=lambda x: x.cpu_time_ns, reverse=True)
        elif args.order == 'composite':
            data_list.sort(key=lambda x: x.energy_impact, reverse=True)

        elapsed_time = datetime.datetime.now() - start_loop_time
        elapsed_time_ms = elapsed_time.total_seconds() * 1000

        current_time = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y %z")
        if args.format == 'text':
            print(f"\n*** Sampled system activity ({current_time}) ({elapsed_time_ms:.2f}ms elapsed) ***\n")
            print("*** Running tasks ***\n")

            # for data in data_list:
            #     output = f"PID: {data.pid}, Cmdline: {data.cmdline}"
            #     if args.show_process_energy or args.show_all :
            #         output += f", Energy Impact: {data.energy_impact:.2f}"
            #     output += f", CPU Utilization (%): {data.cpu_utilization:.2f}"
            #     output += f", CPU Time (ns): {data.cpu_time_ns}"
            #     output += f", CPU Wakeups: {data.cpu_wakeups}"
            #     output += f", Memory Usage (MB): {data.memory_usage_mb:.2f}"
            #     if args.ebpf_memory:
            #          output += f", eBPF Memory Usage (MB): {data.ebpf_memory_usage_mb:.2f}"
            #     if args.show_process_io or args.show_all:
            #         output += f", Disk Read Bytes: {data.disk_read_bytes}, Disk Write Bytes: {data.disk_write_bytes}"
            #     if args.show_process_netstats or args.show_all:
            #         output += f", Net RX Packets: {data.net_rx_packets}, Net TX Packets: {data.net_tx_packets}"
            #     print(output)

            headers = ['PID', 'Name']
            if args.show_process_energy or args.show_all:
                headers.append('Energy Impact')
            headers.append('CPU Utilization (%)')
            headers.append('CPU Time (ns)')
            headers.append('CPU Wakeups')
            headers.append('Memory Usage (MB)')
            if args.ebpf_memory:
                headers.append('eBPF Memory Usage (MB)')
            if args.show_process_io or args.show_all:
                headers.extend(['Disk Read Bytes', 'Disk Write Bytes'])
            if args.show_process_netstats or args.show_all:
                headers.extend(['Net RX Packets', 'Net TX Packets'])
            if args.show_command_line or args.show_all:
                headers.append('Command Line')

            # Initialize the list of rows
            rows = []
            for data in data_list:
                row = [data.pid, data.comm]
                if args.show_process_energy or args.show_all:
                    row.append(f"{data.energy_impact:.2f}")
                row.append(f"{data.cpu_utilization:.2f}")
                row.append(data.cpu_time_ns)
                row.append(data.cpu_wakeups)
                if data.is_kernel_thread:
                    row.append('-')
                else:
                    row.append(f"{data.memory_usage_mb:.2f}")

                if args.ebpf_memory:
                    if data.is_kernel_thread:
                        row.append('-')
                    else:
                        row.append(f"{data.ebpf_memory_usage_mb:.2f}")
                if args.show_process_io or args.show_all:
                    row.extend([data.disk_read_bytes, data.disk_write_bytes])
                if args.show_process_netstats or args.show_all:
                    row.extend([data.net_rx_packets, data.net_tx_packets])
                if args.show_command_line or args.show_all:
                    row.append(data.cmdline)

                rows.append(row)

            # Calculate the maximum width for each column
            col_widths = [len(header) for header in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

            # Print the header row
            header_line = ' | '.join(header.ljust(col_widths[i]) for i, header in enumerate(headers))
            print(header_line)
            separator_line = '-+-'.join('-' * col_widths[i] for i in range(len(headers)))
            print(separator_line)

            # Print each data row
            for row in rows:
                row_line = ' | '.join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
                print(row_line)

            if args.flush:
                print('', flush=True)

        else:
            import plistlib

            plist_data = []

            for data in data_list:
                data_dict = {
                    'PID': data.pid,
                    'Name': data.comm
                }

                if args.show_process_energy or args.show_all:
                    data_dict['Energy Impact'] = data.energy_impact

                data_dict['CPU Utilization (%)'] = data.cpu_utilization
                data_dict['CPU Time (ns)'] = data.cpu_time_ns
                data_dict['CPU Wakeups'] = data.cpu_wakeups

                if data.is_kernel_thread:
                    data_dict['Memory Usage (MB)'] = '-'
                else:
                    data_dict['Memory Usage (MB)'] = data.memory_usage_mb

                if args.ebpf_memory:
                    if data.is_kernel_thread:
                        data_dict['eBPF Memory Usage (MB)'] = '-'
                    else:
                        data_dict['eBPF Memory Usage (MB)'] = data.ebpf_memory_usage_mb

                if args.show_process_io or args.show_all:
                    data_dict['Disk Read Bytes'] = data.disk_read_bytes
                    data_dict['Disk Write Bytes'] = data.disk_write_bytes

                if args.show_process_netstats or args.show_all:
                    data_dict['Net RX Packets'] = data.net_rx_packets
                    data_dict['Net TX Packets'] = data.net_tx_packets

                if args.show_command_line or args.show_all:
                    data_dict['Command Line'] = data.cmdline

                plist_data.append(data_dict)

                if args.output_file:
                    with open(args.output_file, 'wb') as f:
                        plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)
                else:
                    plistlib.dump(plist_data, sys.stdout.buffer, fmt=plistlib.FMT_XML)

        cpu_times.clear()
        wakeups.clear()
        rx_packets.clear()
        tx_packets.clear()
        disk_reads.clear()
        disk_writes.clear()

        current_sample += 1
        if sample_count != 0 and current_sample >= sample_count:
            break

except KeyboardInterrupt:
    print("Monitoring stopped.")
