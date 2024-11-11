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
from urllib.parse import parse_qs, urlparse

from bcc import BPF


# We need to run as root. Otherwise we don't need to do anything
if os.geteuid() != 0:
    print("This script must be run as root. Please use sudo")
    sys.exit(1)


# Define the struct to match `pid_comm_t` in eBPF
class PidComm(ctypes.Structure):
    _fields_ = [
        ('pid', ctypes.c_uint32),
        ('comm', ctypes.c_char * 16),
    ]

parser = argparse.ArgumentParser(description='System performance and energy metrics tool')
parser.add_argument('-i', '--sample-rate', type=int, default=5000, help='Sample every N ms [default: 5000ms]')
parser.add_argument('-n', '--sample-count', type=int, default=0, help='Obtain N periodic samples (0=infinite) [default: 0]')
parser.add_argument('-o', '--output-file', type=str, help='Output to file instead of stdout')
parser.add_argument('-r', '--order', type=str, choices=['pid', 'wakeups', 'cputime', 'composite'], default='composite',
                    help='Order process list using specified method [default: composite]')
parser.add_argument('-A', '--show-all', action='store_true',
                    help='Enables all samplers and displays all the available information for each sampler.')
# parser.add_argument('--show-process-energy', action='store_true',
#                     help='''Show per-process energy impact number. This number is a rough
#                             proxy for the total energy the process uses, including CPU,
#                             disk io and networking. The weighting of each is platform
#                             specific. Enabling this implicitly enables sampling of all the
#                             above per-process statistics.''')
parser.add_argument('--show-process-io', action='store_true', help='Show per-process io information')
parser.add_argument('--show-process-netstats', action='store_true', help='Show per-process network information')
parser.add_argument('--show-command-line', action='store_true', help='Shows the full command line arguments')
parser.add_argument('--format', type=str, choices=['text', 'plist'], default='text', help='Display data in specified format [default: text]')
parser.add_argument('--proc-memory', action='store_true', help='Disables eBPF memory sampling')
parser.add_argument('-f', '--flush', action='store_true', help='Flushes after print')

parser.add_argument('-s', '--server', action='store_true', help='Starts a local server to view the data in a browser')
parser.add_argument('--port', type=int, default=9242, help='The port to run the server on')
parser.add_argument('--host', default='localhost', help='The host to run the server on')

parser.add_argument('--rapl', action='store_true', help='Gets the CPU energy with RAPL')
parser.add_argument('--psys', action='store_true', help='Gets the machine energy with RAPL')
parser.add_argument('--rapl-sample-rate', type=int, default=500, help='Sample every N ms [default: 500ms]')


args = parser.parse_args()

if args.output_file:
    sys.stdout = open(args.output_file, 'w')

with open("ebpf_python.c", 'r') as f:
    bpf_program = f.read()

config = configparser.ConfigParser()
config.read('config.conf')

# The energy impact score is calculated based on weights.
# The basic formula is (metric0*weight) + (metric1*weight) + ...
# So the weights depend on the machine you are running on if you want to get the energy impact as close as possible
# to actual energy usage. In the settings file we used the default MacOS weights. If there is no config file we use
# cpu time and ignore the rest.
CPU_WEIGHT = float(config['Weights'].get('CPU_WEIGHT', 1))
WAKEUP_WEIGHT = float(config['Weights'].get('WAKEUP_WEIGHT', 0))
DISK_WRITE_WEIGHT = float(config['Weights'].get('DISK_WRITE_WEIGHT', 0))
DISK_READ_WEIGHT = float(config['Weights'].get('DISK_READ_WEIGHT', 0))
NETWORK_WRITE_WEIGHT = float(config['Weights'].get('NETWORK_WRITE_WEIGHT', 0))
NETWORK_READ_WEIGHT = float(config['Weights'].get('NETWORK_READ_WEIGHT', 0))
MEMORY_WEIGHT = float(config['Weights'].get('MEMORY_WEIGHT', 0))

num_cpus = os.cpu_count()

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
            'cpu_utilization', 'energy_impact'
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
                if field == 'cpu_utilization' or field == 'energy_impact':
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
            'energy_impact': {}
        }
        for item in self.data[index:]:
            if item['current_time'] not in time_data['energy_impact']:
                time_data['energy_impact'][item['current_time']] = 0

            for process in item['data']:
                time_data['energy_impact'][item['current_time']] += process['energy_impact']

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


def rapl_metrics_provider_thread(interval, params, stop_event):
    binary = './providers/rapl/metric-provider-binary'

    if not os.path.isfile(binary):
        print('Could not find metric provider bin. Did you run make?')
        stop_event.set()
        sys.exit(1)

    try:
        metrics_process = subprocess.Popen(
            ['stdbuf', '-oL', binary, '-i', str(interval), str(params)],
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
        # Terminate the metrics provider process if it's still running
        if metrics_process.poll() is None:
            print("Terminating metrics provider process...")
            metrics_process.terminate()
            try:
                metrics_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Metrics provider did not terminate, killing it.")
                metrics_process.kill()

def parse_metrics_output(output):
    # Implement your parsing logic here
    try:
        # Example parsing: convert output to float
        return float(output)
    except ValueError:
        print(f"Invalid output from metrics provider: {output}")
        return None

def print_text(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums):
    print(f"\n*** Sampled system activity ({current_time}) ({elapsed_time_ms:.2f}ms elapsed) ***\n")
    print("*** Running tasks ***\n")

    headers = ['PID', 'Name', 'Energy Impact', 'CPU Utilization (%)', 'CPU Time (ns)', 'CPU Wakeups', 'Memory Usage (MB)']
    if args.show_process_io or args.show_all:
        headers.extend(['Disk Read Bytes', 'Disk Write Bytes'])
    if args.show_process_netstats or args.show_all:
        headers.extend(['Net RX Packets', 'Net TX Packets'])
    if args.show_command_line or args.show_all:
        headers.append('Command Line')

    # Initialize the list of rows
    rows = []
    for data in data_list:
        row = [data.pid, data.comm, f"{data.energy_impact():.2f}", f"{data.cpu_utilization():.2f}", data.cpu_time_ns, data.cpu_wakeups]
        if data.is_kernel_thread:
            row.append('-')
        else:
            row.append(f"{data.memory_usage_mb():.2f}")
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

    if rapl_energy_sums:
        print('')

    for p, r in sorted(rapl_energy_sums.items()):
        print(f"RAPL energy ({p}): {r}mJ")

    if args.flush:
        print('', flush=True)

def print_xml(args, data_list, current_time, elapsed_time_ms):
    import plistlib

    plist_data = []

    for data in data_list:
        data_dict = {
            'PID': data.pid,
            'Name': data.comm,
            'Current Time': current_time,
            'Elapsed Time': elapsed_time_ms,
            'Energy Impact': data.energy_impact(),
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

        if args.show_command_line or args.show_all:
            data_dict['Command Line'] = data.cmdline

        plist_data.append(data_dict)

    if args.output_file:
        with open(args.output_file, 'ab') as f:
            plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)
    else:
        plistlib.dump(plist_data, sys.stdout.buffer, fmt=plistlib.FMT_XML)

        if args.flush:
            print('', flush=True)

class BPFData:

    def __init__(self):
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

    def memory_usage_mb(self):
        return self.memory_usage / (1024 * 1024)

    def cpu_utilization(self):
        if self.pid == 0:
            # As pid 0 is multiple programs in one we need to get the idle_time counter from ebpf
            # The key is the cpu number
            idle_times = b.get_table("idle_time_ns")
            self.cpu_time_ns = sum([idle_times[cpu_id].value for cpu_id in idle_times.keys()])

        return (self.cpu_time_ns / (interval_ns * num_cpus)) * 100

    def energy_impact(self):
        if self.pid == 0:
            # We can't really assign a value to the system being idle on one to n cores. Modern CPUs will go in a
            # sleep state when they are not used and it is quite hard to estimate the impact this has.
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
            'energy_impact': self.energy_impact()
        }

def get_data(stop_event):

    try:

        current_sample = 0

        # Print header
        if not args.output_file:
            print("Starting powerletrics monitoring. Press Ctrl+C to stop.")

        while not stop_event.is_set():

            start_loop_time = datetime.datetime.now()

            # This needs refactoring at some stage as if you press CTRL-C while in the sleep the process will not exit
            # right away
            time.sleep(sample_interval_sec)

            # Retrieve data from eBPF maps
            cpu_times = b.get_table("cpu_time_ns")
            wakeups = b.get_table("cpu_wakeups")
            rx_packets = b.get_table("net_rx_packets")
            tx_packets = b.get_table("net_tx_packets")
            disk_reads = b.get_table("disk_read_bytes")
            disk_writes = b.get_table("disk_write_bytes")
            idle_times = b.get_table("idle_time_ns")
            pid_comm_map = b.get_table("pid_comm_map")


            data_list = []

            for pid_key in cpu_times.keys():

                pid = pid_key.value
                data = BPFData()
                data.pid = pid
                data.cpu_time_ns = cpu_times[pid_key].value
                data.cpu_wakeups = wakeups[pid_key].value if pid_key in wakeups else 0
                data.net_rx_packets = rx_packets[pid_key].value if pid_key in rx_packets else 0
                data.net_tx_packets = tx_packets[pid_key].value if pid_key in tx_packets else 0
                data.disk_read_bytes = disk_reads[pid_key].value if pid_key in disk_reads else 0
                data.disk_write_bytes = disk_writes[pid_key].value if pid_key in disk_writes else 0

                pid_comm = pid_comm_map.get(ctypes.c_uint32(pid))
                if pid_comm:
                    data.comm = pid_comm.comm.decode('utf-8', 'replace')
                else:
                    data.comm = "<unknown>"

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
                    ebpf_mem_usages = b.get_table("mem_usage_bytes")
                    data.memory_usage = ebpf_mem_usages[pid_key].value if pid_key in ebpf_mem_usages else 0


                # PID 0 is an odd thing.
                if data.pid == 0:
                    data.cmdline = "<idle>"
                    data.comm = "Kernel Idle"
                    data.memory_usage = 0
                    data.is_kernel_thread = True
                else:
                    try:
                        with open(f"/proc/{data.pid}/cmdline", 'rb') as f:
                            data.cmdline = f.read().replace(b'\x00', b' ').strip().decode('utf-8', 'replace')
                            if data.cmdline == '':
                                data.is_kernel_thread = True
                    except:
                        data.cmdline = ""


                data_list.append(data)

            # Sort data based on the selected order
            if args.order == 'pid':
                data_list.sort(key=lambda x: x.pid)
            elif args.order == 'wakeups':
                data_list.sort(key=lambda x: x.cpu_wakeups, reverse=True)
            elif args.order == 'cputime':
                data_list.sort(key=lambda x: x.cpu_time_ns, reverse=True)
            elif args.order == 'composite':
                data_list.sort(key=lambda x: x.energy_impact(), reverse=True)


            now = datetime.datetime.now()
            elapsed_time = now - start_loop_time
            elapsed_time_ms = elapsed_time.total_seconds() * 1000

            current_time = now.strftime("%a %b %d %H:%M:%S %Y %z")

            rapl_energy_sums = {}
            if args.rapl:
                readings_in_range = [
                    data
                    for time, data in rapl_reading.items()
                    if start_loop_time <= time <= now
                ]

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
                    print_text(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums)
                else:
                    print_xml(args, data_list, current_time, elapsed_time_ms, rapl_energy_sums)

            cpu_times.clear()
            wakeups.clear()
            rx_packets.clear()
            tx_packets.clear()
            disk_reads.clear()
            disk_writes.clear()
            idle_times.clear()
            pid_comm_map.clear()


            current_sample += 1
            if sample_count != 0 and current_sample >= sample_count:
                break

    except KeyboardInterrupt:
        print("Monitoring stopped.")

import http.server
import os

class LittleServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.directory = 'http'
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
        # Add headers to prevent caching
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

if __name__ == '__main__':

    stop_event = threading.Event()

    ebpf_thread = threading.Thread(target=get_data, args=(stop_event,)).start()

    if args.rapl:
        cpu_metrics_thread = threading.Thread(target=rapl_metrics_provider_thread, args=(args.rapl_sample_rate, '', stop_event))
        cpu_metrics_thread.start()

    if args.psys:
        psys_metrics_thread = threading.Thread(target=rapl_metrics_provider_thread, args=(args.rapl_sample_rate, '-p', stop_event,))
        psys_metrics_thread.start()

    socketserver.TCPServer.allow_reuse_address = True

    if args.server:
        with socketserver.TCPServer((args.host, args.port), LittleServer) as httpd:
            print(f"Serving on port http://{args.host}:{args.port}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("Shutting down server...")
                stop_event.set()
                httpd.shutdown()
                httpd.server_close()
                sys.exit(0)
