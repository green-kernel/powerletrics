#!/usr/bin/env python3

import bisect
from collections import defaultdict
import json
import os
import argparse
import threading
import time
import sys
import configparser
import datetime
import ctypes
import http.server
import socketserver
import subprocess
import signal
from urllib.parse import parse_qs, urlparse
import http.server

from bcc import BPF

def is_root():
    return os.geteuid() == 0

def run_as_root():
    if not is_root():
        print("This script requires root privileges. Attempting to re-run with sudo...")
        try:
            cmd = ['sudo', sys.executable] + sys.argv
            os.execvp('sudo', cmd)
        except Exception as e:
            print(f"Failed to re-execute script as root: {e}")
            sys.exit(1)

# We need to run as root. Otherwise we don't need to do anything. That is why we do it right away
run_as_root()

current_dir = os.path.dirname(os.path.abspath(__file__))

httpd = None  # Global variable for the server
stop_event = threading.Event() # Global variable when sets everything should shutdown
thread_pid_list = []

# This is a replacement for time.sleep as we need to check periodically if we need to exit
# We choose a max exit time of one second as we don't want to wake up too often.
def sleeper(duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        if stop_event.is_set():
            return
        time.sleep(0.5)


parser = argparse.ArgumentParser(description='System performance and energy metrics tool')
parser.add_argument('-i', '--sample-rate', type=int, default=5000, help='Sample every N ms [default: 5000ms]')
parser.add_argument('-n', '--sample-count', type=int, default=0, help='Obtain N periodic samples (0=infinite) [default: 0]')
parser.add_argument('-o', '--output-file', type=str, help='Output to file instead of stdout')
parser.add_argument('-r', '--order', type=str, choices=['pid', 'wakeups', 'cputime', 'composite'], default='composite',
                    help='Order process list using specified method [default: composite]')
parser.add_argument('-A', '--show-all', action='store_true',
                    help='Enables all samplers and displays all the available information for each sampler.')
# parser.add_argument('--show-process-energy', action='store_true',
#                     help='''Show per-process energy footprint number. This number is a rough
#                             proxy for the total energy the process uses, including CPU,
#                             disk io and networking. The weighting of each is platform
#                             specific. Enabling this implicitly enables sampling of all the
#                             above per-process statistics.''')
parser.add_argument('--show-process-io', action='store_true', help='Show per-process io information')
parser.add_argument('--show-process-netstats', action='store_true', help='Show per-process network information')
parser.add_argument('--show-command-line', action='store_true', help='Shows the full command line arguments')
parser.add_argument('--short', action='store_true', help='Removes all processes that have an energy footprint of 0 from the output.')
parser.add_argument('--format', type=str, choices=['text', 'plist'], default='text', help='Display data in specified format [default: text]')
parser.add_argument('--proc-memory', action='store_true', help='Disables eBPF memory sampling')
parser.add_argument('-f', '--flush', action='store_true', help='Flushes after print')
parser.add_argument('-c', '--clear', action='store_true', help='Clears the screen on new data')

parser.add_argument('-s', '--server', action='store_true', help='Starts a local server to view the data in a browser')
parser.add_argument('--port', type=int, default=9242, help='The port to run the server on')
parser.add_argument('--host', default='localhost', help='The host to run the server on')

parser.add_argument('--rapl', action='store_true', help='Gets the CPU energy with RAPL. You will need to run make to use this feature')
parser.add_argument('--psys', action='store_true', help='Gets the machine energy with RAPL. You will need to run make to use this feature')
parser.add_argument('--rapl-sample-rate', type=int, default=500, help='Sample every N ms [default: 500ms]')
parser.add_argument('--overhead', action='store_true', help='Outputs the overhead powerletrics has on the system')
parser.add_argument('--thread', action='store_true', help='Shows if the process is a thread')


args = parser.parse_args()

def sigint_handler(_, __):
    global stop_event, httpd
    if stop_event.is_set():
        # If you press CTRL-C the second time we bail
        print('Bailing, system may be in an inconsistent state!')
        sys.exit(2)

    stop_event.set()
    print('Terminating all processes. Please be patient, this might take a few seconds.')

    if httpd:
        httpd.shutdown()
        httpd.server_close()

signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, sigint_handler)

if args.output_file:
    sys.stdout = open(args.output_file, 'w')

with open(os.path.join(current_dir, 'ebpf_python.c'), 'r') as ebpf_file:
    bpf_program = ebpf_file.read()

config = configparser.ConfigParser()

if os.path.isfile('/etc/powerletrics'):
    config.read('/etc/powerletrics')
else:
    config.read(os.path.join(current_dir, 'config.conf'))

# The energy footprint score is calculated based on weights.
# The basic formula is (metric0*weight) + (metric1*weight) + ...
# So the weights depend on the machine you are running on if you want to get the energy footprint as close as possible
# to actual energy usage. In the settings file we used the default MacOS weights. If there is no config file we use
# cpu time and ignore the rest.
CPU_WEIGHT = float(config['Weights'].get('CPU_WEIGHT', 1))
WAKEUP_WEIGHT = float(config['Weights'].get('WAKEUP_WEIGHT', 0))
DISK_WRITE_WEIGHT = float(config['Weights'].get('DISK_WRITE_WEIGHT', 0))
DISK_READ_WEIGHT = float(config['Weights'].get('DISK_READ_WEIGHT', 0))
NETWORK_WRITE_WEIGHT = float(config['Weights'].get('NETWORK_WRITE_WEIGHT', 0))
NETWORK_READ_WEIGHT = float(config['Weights'].get('NETWORK_READ_WEIGHT', 0))
MEMORY_WEIGHT = float(config['Weights'].get('MEMORY_WEIGHT', 0))

bpf_program = bpf_program.replace('__COMM_LENGTH__', config['eBPF'].get('COMM_LENGTH', 4096))

num_cpus = len(os.sched_getaffinity(0))

b = BPF(text=bpf_program)

sample_interval_sec = args.sample_rate / 1000  # Convert ms to seconds
interval_ns = sample_interval_sec * 1e9  # Convert to nanoseconds
sample_count = args.sample_count
page_size = os.sysconf('SC_PAGE_SIZE')
time_to_remove = 5 * 60  # 5 minutes ago

class DB():
    def __init__(self):
        self.data = []

    def create_table_data_optimized(self, since=None):
        # We could also do this on add_data, but for now I want to do it here as this gives me greater flexibility
        # and I am not quite sure where this will be going
        numeric_fields = [
            'cpu_time_ns', 'cpu_wakeups', 'memory_usage', 'memory_usage_mb',
            'net_rx_packets', 'net_tx_packets', 'disk_read_bytes', 'disk_write_bytes',
            'cpu_utilization', 'energy_footprint'
        ]

        pid_map = defaultdict(lambda: {field: 0 for field in numeric_fields})

        if since is not None:
            index = bisect.bisect_right(self.data, since, key=lambda x: x['current_time'])
        else:
            index = 0

        ddata = self.data[index:] # We need to save this here as we will need to down below for len

        for item in ddata:
            for process in item['data']:
                if process['is_kernel_thread'] == True:
                    continue

                pid = process['pid']
                proc_ref = pid_map[pid]

                if 'cmdline' not in proc_ref:
                    proc_ref['cmdline'] = process['cmdline']
                    proc_ref['comm'] = process['comm']
                    proc_ref['current_time'] = item['current_time']

                for field in numeric_fields:
                    proc_ref[field] += process.get(field, 0)


        pid_array = []
        for pid, process_data in pid_map.items():
            for field in numeric_fields:
                if field == 'cpu_utilization' or field == 'energy_footprint':
                    process_data[field] = process_data[field] / len(ddata)

                if isinstance(process_data[field], float):
                    process_data[field] = round(process_data[field], 2)

            pid_array.append({'pid': pid, **process_data})

        return pid_array

    def get_timed_data(self, since):

        if since is not None:
            index = bisect.bisect_right(self.data, since, key=lambda x: x['current_time'])
        else:
            index = 0

        time_data = {
            'energy_footprint': {}
        }
        for item in self.data[index:]:
            if item['current_time'] not in time_data['energy_footprint']:
                time_data['energy_footprint'][item['current_time']] = 0

            for process in item['data']:
                time_data['energy_footprint'][item['current_time']] += process['energy_footprint']

            for p, v in item['rapl'].items():
                if p not in time_data:
                    time_data[p] = {}
                time_data[p][item['current_time']] = v

        return json.dumps(time_data)


    def add_data(self, data_to_add):

        now = datetime.datetime.now().timestamp()
        cutoff_time = now - time_to_remove

        # Remove data that is older than 5 min
        index = bisect.bisect_left(self.data, cutoff_time, key=lambda x: x['current_time'])
        self.data = self.data[index:]

        # We make sure to add to the array sorted by time. Like this retrieving and cleanup with since is far easier
        bisect.insort(self.data, data_to_add, key=lambda x: x['current_time'])

    def dump_data(self, since=None):
        if since is not None:
            since = float(since)
            index = bisect.bisect_right(self.data, since, key=lambda x: x['current_time'])
            return json.dumps(self.data[index:])

        return json.dumps(self.data)

    def dump_table_data(self, since=None):
        return json.dumps(self.create_table_data_optimized(since))


db = DB()

rapl_reading = {}

def ensure_metrics_provider_built(binary_path):
    global stop_event

    if not os.path.isfile(binary_path):
        print(f"Metrics provider binary not found at {binary_path}. Attempting to build it with make...")
        try:
            subprocess.run(['make'], cwd=current_dir, check=True)
            if not os.path.isfile(binary_path):
                print(f"Failed to build the metrics provider binary at {binary_path}.")
                stop_event.set()
                sys.exit(1)
            else:
                print("Successfully built the metrics provider binary.")
        except subprocess.CalledProcessError as e:
            print(f"Make failed with error: {e}")
            stop_event.set()
            sys.exit(1)

def rapl_metrics_provider_thread(interval, params):
    binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), './providers/rapl/metric-provider-binary')

    ensure_metrics_provider_built(binary_path)

    if not os.path.isfile(binary_path):
        print('Could not find metric provider bin. Did you run $ make?')
        stop_event.set()
        sys.exit(1)

    try:
        metrics_process = subprocess.Popen(
            ['stdbuf', '-oL', binary_path, '-i', str(interval), str(params)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        print(f"Error starting metrics provider: {e}")
        stop_event.set()
        sys.exit(2)

    try:
        while not stop_event.is_set():
            # if error_line := metrics_process.stderr.readline():
            #     print(f"There is an error in metrics provider: {error_line}")
            #     stop_event.set()
            #     sys.exit(3)

            output = metrics_process.stdout.readline()
            if output == '' and metrics_process.poll() is not None:
                print("Metrics provider process has terminated.")
                break
            if output:
                parsed_data = output.strip().split()
                rapl_reading[datetime.datetime.fromtimestamp(int(parsed_data[0]) / 1e6)] = {
                    'energy': float(parsed_data[1]) / 100,
                    'package': parsed_data[2]
                }
            else:
                time.sleep(0.1)
    finally:
        if metrics_process.poll() is None:
            print("Terminating metrics provider process...")
            metrics_process.terminate()
            try:
                metrics_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Metrics provider did not terminate, killing it.")
                metrics_process.kill()

def print_text(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums):

    overhead_energy_footprint = 0
    overhead_cpu_util = 0

    print(f"\n*** Sampled system activity ({current_time}) ({elapsed_time_ms:.2f}ms elapsed) ***\n")
    print("*** Running tasks ***\n")

    headers = ['PID', 'Name', 'Energy Footprint', 'CPU Utilization (%)', 'CPU Time (ns)', 'CPU Wakeups', 'Memory Usage (MB)']
    if args.show_process_io or args.show_all:
        headers.extend(['Disk Read Bytes', 'Disk Write Bytes'])
    if args.show_process_netstats or args.show_all:
        headers.extend(['Net RX Packets', 'Net TX Packets'])
    if args.thread or args.show_all:
        headers.append("Is Thread")
    if args.show_command_line or args.show_all:
        headers.append('Command Line')

    # Initialize the list of rows
    rows = []
    for data in data_list:

        if args.short and data.energy_footprint() < 0.01:
            continue

        row = [data.pid, data.comm, f"{data.energy_footprint():.2f}", f"{data.cpu_utilization():.2f}", data.cpu_time_ns, data.cpu_wakeups]
        if data.is_kernel_thread:
            row.append('-')
        else:
            row.append(f"{data.memory_usage_mb():.2f}")
        if args.show_process_io or args.show_all:
            row.extend([data.disk_read_bytes, data.disk_write_bytes])
        if args.show_process_netstats or args.show_all:
            row.extend([data.net_rx_packets, data.net_tx_packets])
        if args.thread or args.show_all:
            row.append(data.is_thread)
        if args.show_command_line or args.show_all:
            row.append(data.cmdline)

        rows.append(row)

        if args.overhead and data.pid in thread_pid_list:
            overhead_energy_footprint += data.energy_footprint()
            overhead_cpu_util += data.cpu_utilization()

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

    if rapl_energy_sums:
        print('')

    for p, r in sorted(rapl_energy_sums.items()):
        print(f"RAPL energy ({p}): {r}mJ")

    if args.overhead:
        print(f"Powerletrics overhead: {overhead_energy_footprint:.2f} (energy footprint), {overhead_cpu_util:.2f} (cpu util)")

    if args.flush:
        print('', flush=True)

def print_xml(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums):
    import plistlib

    plist_data = []

    for data in data_list:

        if args.short and data.energy_footprint() < 0.01:
            continue

        data_dict = {
            'PID': data.pid,
            'Name': data.comm,
            'Current Time': current_time,
            'Elapsed Time': elapsed_time_ms,
            'Energy Footprint': data.energy_footprint(),
            'CPU Utilization (%)': data.cpu_utilization(),
            'CPU Time (ns)': data.cpu_time_ns,
            'CPU Wakeups': data.cpu_wakeups,
        }

        if data.is_kernel_thread:
            data_dict['Memory Usage (MB)'] = '-'
        else:
            data_dict['Memory Usage (MB)'] = data.memory_usage_mb()

        if args.show_process_io or args.show_all:
            data_dict['Disk Read Bytes'] = data.disk_read_bytes
            data_dict['Disk Write Bytes'] = data.disk_write_bytes

        if args.show_process_netstats or args.show_all:
            data_dict['Net RX Packets'] = data.net_rx_packets
            data_dict['Net TX Packets'] = data.net_tx_packets

        if args.thread or args.show_all:
            data_dict['Thread'] = data.is_thread

        if args.show_command_line or args.show_all:
            data_dict['Command Line'] = data.cmdline

        for p, r in sorted(rapl_energy_sums.items()):
            data_dict[f"RAPL energy ({p})"] = r

        plist_data.append(data_dict)

    if args.output_file:
        with open(args.output_file, 'ab') as f:
            plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)
    else:
        plistlib.dump(plist_data, sys.stdout.buffer, fmt=plistlib.FMT_XML)

        if args.flush:
            print('', flush=True)

start_loop_time = None

class BPFData:

    def __init__(self, elapsed_time_ns):
        self.elapsed_time_ns = elapsed_time_ns
        self.pid = -1
        self.comm = ""
        self.cmdline = ""
        self.cpu_time_ns = 0
        self.cpu_wakeups = 0
        self.memory_usage = 0
        self.net_rx_packets = 0
        self.net_tx_packets = 0
        self.disk_read_bytes = 0
        self.disk_write_bytes = 0
        self.is_kernel_thread = False
        self.is_thread = True

    def memory_usage_mb(self):
        return self.memory_usage / (1024 * 1024)

    def cpu_utilization(self):
        return (self.cpu_time_ns / (self.elapsed_time_ns * num_cpus)) * 100

    def energy_footprint(self):
        if self.pid == 0:
            # We can't really assign a value to the system being idle on one to n cores. Modern CPUs will go in a
            # sleep state when they are not used and it is quite hard to estimate the footprint this has.
            return 0

        return (CPU_WEIGHT * self.cpu_utilization()) + \
            (WAKEUP_WEIGHT * self.cpu_wakeups) + \
            (DISK_WRITE_WEIGHT * self.disk_write_bytes) + \
            (DISK_READ_WEIGHT * self.disk_read_bytes) + \
            (NETWORK_WRITE_WEIGHT * self.net_tx_packets) + \
            (NETWORK_READ_WEIGHT * self.net_rx_packets) + \
            (MEMORY_WEIGHT * self.memory_usage)

    def to_dict(self):
        return {
            'pid': self.pid,
            'comm': self.comm,
            'cmdline': self.cmdline,
            'cpu_time_ns': self.cpu_time_ns,
            'cpu_wakeups': self.cpu_wakeups,
            'memory_usage': self.memory_usage,
            'memory_usage_mb': self.memory_usage_mb(),
            'net_rx_packets': self.net_rx_packets,
            'net_tx_packets': self.net_tx_packets,
            'disk_read_bytes': self.disk_read_bytes,
            'disk_write_bytes': self.disk_write_bytes,
            'is_kernel_thread': self.is_kernel_thread,
            'cpu_utilization': self.cpu_utilization(),
            'energy_footprint': self.energy_footprint()
        }


def get_data():
    prev_time = last_time = datetime.datetime.now()
    current_sample = 0

    if not args.output_file:
        print("Starting powerletrics monitoring. Press Ctrl+C to stop.")

    while not stop_event.is_set():

        sleeper(sample_interval_sec)

        if stop_event.is_set():
            break

        now = datetime.datetime.now()
        elapsed_time_ns = (now - prev_time).total_seconds() * 1e9  # Convert to nanoseconds
        elapsed_time_ms = elapsed_time_ns / 1e6
        prev_time = datetime.datetime.now()

        # Retrieve data from eBPF maps
        cpu_times_map = b.get_table("cpu_time_ns")
        wakeups_map = b.get_table("cpu_wakeups")
        rx_packets_map = b.get_table("net_rx_packets")
        tx_packets_map = b.get_table("net_tx_packets")
        disk_reads_map = b.get_table("disk_read_bytes")
        disk_writes_map = b.get_table("disk_write_bytes")
        idle_times_map = b.get_table("idle_time_ns")
        pid_comm_map = b.get_table("pid_comm_map")
        ebpf_mem_usages_map = b.get_table("mem_usage_bytes")
        ebpf_time_ns_map = b.get_table("ebpf_time_ns")

        cpu_times = {key.value: value.value for key, value in cpu_times_map.items()}
        wakeups = {key.value: value.value for key, value in wakeups_map.items()}
        rx_packets = {key.value: value.value for key, value in rx_packets_map.items()}
        tx_packets = {key.value: value.value for key, value in tx_packets_map.items()}
        disk_reads = {key.value: value.value for key, value in disk_reads_map.items()}
        disk_writes = {key.value: value.value for key, value in disk_writes_map.items()}
        pid_comm = {key.value: value.comm for key, value in pid_comm_map.items()}
        pid_thread = {key.value: value.is_thread for key, value in pid_comm_map.items()}
        idle_times = {key.value: value.value for key, value in idle_times_map.items()}
        ebpf_mem_usages = {key.value: value.value for key, value in ebpf_mem_usages_map.items()}
        ebpf_time_ns = {key.value: value.value for key, value in ebpf_time_ns_map.items()}

        cpu_times_map.clear()
        wakeups_map.clear()
        rx_packets_map.clear()
        tx_packets_map.clear()
        disk_reads_map.clear()
        disk_writes_map.clear()
        idle_times_map.clear()
        #pid_comm_map.clear()
        ebpf_mem_usages_map.clear()
        ebpf_time_ns_map.clear()

        data_list = []

        for pid_key in cpu_times.keys():

            data = BPFData(elapsed_time_ns)
            data.pid = pid_key
            data.cpu_time_ns = cpu_times[pid_key]
            data.cpu_wakeups = wakeups[pid_key] if pid_key in wakeups else 0
            data.net_rx_packets = rx_packets[pid_key] if pid_key in rx_packets else 0
            data.net_tx_packets = tx_packets[pid_key] if pid_key in tx_packets else 0
            data.disk_read_bytes = disk_reads[pid_key] if pid_key in disk_reads else 0
            data.disk_write_bytes = disk_writes[pid_key] if pid_key in disk_writes else 0
            data.is_thread = pid_thread[pid_key] if pid_key in pid_thread else False

            comm = pid_comm.get(pid_key)
            if comm:
                data.comm = comm.decode('utf-8', 'replace')
            else:
                data.comm = '<unknown>'

            if args.overhead and data.pid in thread_pid_list:
                # We can add the time that ebpf takes to the powerletrics process.
                # This is mathematically not 100% correct as we would need to substract this from all other processes. But this would create even more overhead and the added time is minimum.
                # This is more a gimmic to be honest
                data.cpu_time_ns = data.cpu_time_ns + sum([ebpf_time_ns[cpu_id] for cpu_id in ebpf_time_ns.keys()])


            # We currently keep both implementations to debug the difference
            if args.proc_memory:
                if not data.is_kernel_thread:
                    try:
                        with open(f"/proc/{data.pid}/statm", 'r') as f:
                            statm = f.readline().split()
                            if len(statm) >= 2:
                                total_pages = int(statm[0])
                                data.memory_usage = total_pages * page_size
                    except:
                        data.memory_usage = 0  # Process might have exited
                else:
                    # Kernel threads don't have user space memory
                    data.memory_usage = 0
            else:
                data.memory_usage = ebpf_mem_usages[pid_key] if pid_key in ebpf_mem_usages else 0


            if args.show_command_line or args.show_all:
                try:
                    with open(f"/proc/{data.pid}/cmdline", 'rb') as f:
                        data.cmdline = f.read().replace(b'\x00', b' ').strip().decode('utf-8', 'replace')
                        if data.cmdline == '':
                            data.is_kernel_thread = True
                except:
                    data.cmdline = ""

            data_list.append(data)

        # We need to create the idle task
        idle_data = BPFData(elapsed_time_ns)
        idle_data.pid = 0
        idle_data.cmdline = "<idle>"
        idle_data.comm = "Kernel Idle"
        idle_data.memory_usage = 0
        idle_data.is_kernel_thread = True
        idle_data.is_thread = False
        idle_data.cpu_time_ns = sum([idle_times[cpu_id] for cpu_id in idle_times.keys()])
        data_list.append(idle_data)

        # Sort data based on the selected order
        if args.order == 'pid':
            data_list.sort(key=lambda x: x.pid)
        elif args.order == 'wakeups':
            data_list.sort(key=lambda x: x.cpu_wakeups, reverse=True)
        elif args.order == 'cputime':
            data_list.sort(key=lambda x: x.cpu_time_ns, reverse=True)
        elif args.order == 'composite':
            data_list.sort(key=lambda x: x.energy_footprint(), reverse=True)


        current_time = now.strftime("%a %b %d %H:%M:%S %Y %z")

        rapl_energy_sums = {}
        if args.rapl:
            readings_in_range = [
                data
                for time, data in rapl_reading.items()
                if last_time <= time <= datetime.datetime.now()
            ]

            last_time = datetime.datetime.now()

            for data in readings_in_range:
                rapl_energy_sums[data['package']] = round(rapl_energy_sums.get(data['package'], 0) + data['energy'], 2)

        if args.server:
            db.add_data({
                'data': [item.to_dict() for item in data_list],
                'current_time': now.timestamp(),
                'elapsed_time_ms': elapsed_time_ms,
                'rapl': rapl_energy_sums,
            })
        else:
            if args.format == 'text':
                if args.clear:
                    print("\033c", end="")
                print_text(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums)
            else:
                print_xml(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums)

        current_sample += 1
        if sample_count != 0 and current_sample >= sample_count:
            break

class LittleServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.directory = os.path.join(current_dir,'http')
        super().__init__(*args, directory=self.directory, **kwargs)

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        if path == '/':
            self.path = '/index.html'
        elif path == '/get_data':
            since = query.get('since', [None])[0]
            response_data = db.dump_data(since)
            self.send_json_data(response_data)
            return
        elif path == '/get_table_data':
            since = query.get('since', [None])[0]
            response_data = db.dump_table_data(since)
            self.send_json_data(response_data)
            return
        elif path == '/get_timed_data':
            since = query.get('since', [None])[0]
            response_data = db.get_timed_data(since)
            self.send_json_data(response_data)
            return

        return super().do_GET()

    def send_json_data(self, data_to_send):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(data_to_send.encode('utf-8'))

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

def populate_all_native_thread_ids():
    global thread_pid_list
    for thread in threading.enumerate():
        try:
            thread_pid_list.append(thread.native_id)
        except AttributeError:
            pass

def main():
    threads = []

    ebpf_thread = threading.Thread(target=get_data)
    ebpf_thread.start()
    threads.append(ebpf_thread)

    if args.rapl:
        cpu_metrics_thread = threading.Thread(target=rapl_metrics_provider_thread, args=(args.rapl_sample_rate, ''))
        cpu_metrics_thread.start()
        threads.append(cpu_metrics_thread)

    if args.psys:
        psys_metrics_thread = threading.Thread(target=rapl_metrics_provider_thread, args=(args.rapl_sample_rate, '-p'))
        psys_metrics_thread.start()
        threads.append(psys_metrics_thread)

    socketserver.TCPServer.allow_reuse_address = True
    socketserver.TCPServer.timeout = 5

    if args.server:
        httpd = socketserver.TCPServer((args.host, args.port), LittleServer)
        print(f"Serving on port http://{args.host}:{args.port}")

        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.start()
        threads.append(server_thread)

    populate_all_native_thread_ids()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
