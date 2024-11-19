# powermetrics on 🐧 => powerletrics

PowerLetrics is an open-source framework designed to monitor and analyze power consumption metrics at the process level on Linux. Similar to how `top` displays memory or CPU time, PowerLetrics provides the "Energy Footprint" of each process in real-time. This project is still in the early stages of development. Please test it and submit any issues.

This project is heavily influenced by the `powermetrics` program on macOS.


## Install and run

1. You need to install bcc on your system which should include all the python bindings

https://github.com/iovisor/bcc/blob/master/INSTALL.md

2. You can then install the program with `pip install powerletrics`. Please note that if you are using a `venv` you will need to create it with `--system-site-packages` as otherwise we don't have access to the bcc libs

3. If you want to use *RAPL* and *PSYS* data you need to build the binaries. You will need `gcc` and `make` on your system.
PowerLetrics will try and build everything on the first run for you.

4. You can then run the program from the shell:
```bash
powerletrics -i 1000 --show-all
```

### CPU Energy

There is also the option to get the CPU energy from RAPL. You can activate this with ``--rapl``.

If your computer support it you can also get the PSYS energy with ``--psys``.

We don't enable this by default as we want to make the program runnable in a VM so people can test it easily and we want the default to work in all environments.

If you want to use this feature you will need to install `gcc` on your machine and build the tools with `make`

## Screenshot

![How it looks](Screenshot.png "PowerLetrics in action")

## Screenshot with server

![How the HTML server looks](Screenshot_Server.png "PowerLetrics bundled HTML server")


## Parameters

### `-i` / `--sample-rate`
- **Default**: 5000 (milliseconds)
- **Description**: Specifies the time interval (in milliseconds) between samples. The program will capture data at this interval. For example, a value of 5000ms means data will be collected every 5 seconds.

### `-n` / `--sample-count`
- **Default**: 0 (infinite)
- **Description**: Defines how many samples to take before the program stops. If set to 0, the program will continue to sample indefinitely until manually stopped.

### `-o` / `--output-file`
- **Description**: If specified, the output will be written to the provided file instead of the standard output (console).

### `-r` / `--order`
- **Choices**: `pid`, `wakeups`, `cputime`, `composite`
- **Default**: `composite`
- **Description**: Sets the sorting method for the displayed process list:
  - `pid`: Sort by process ID.
  - `wakeups`: Sort by the number of CPU wakeups.
  - `cputime`: Sort by CPU time.
  - `composite`: Sort by the composite energy impact (a weighted combination of several factors, like CPU, memory, and disk usage).

### `--show-all`
- **Description**: Enables all available samplers and shows all the information from each one. This includes process energy impact, I/O stats, and network stats.

### `--show-process-io`
- **Description**: Displays per-process I/O statistics, such as disk read and write bytes.

### `--show-process-netstats`
- **Description**: Displays per-process network statistics, including the number of received and transmitted network packets.

### `--show-command-line`
- **Description**: Displays the full command-line arguments for each process.

### `--format`
- **Choices**: `text`, `plist`
- **Default**: `text`
- **Description**: Specifies the format in which the output will be displayed:
  - `text`: Human-readable text format.
  - `plist`: Property list (XML) format, useful for programmatic analysis.

### `--proc-memory`
- **Description**: The default mode is to get memory using ebpf. If this doesn't work you can also use the memory from the proc filesystem. This will be slower as for every process we need to open the /proc file and parse it.

### `--flush`
- **Description**: Forces flushing of the output after each print. This is useful when writing output to files or when immediate display is necessary.

### `--server`
- **Description**: Start a webserver running @ http://localhost:9242 that displays data in nice HTML format with charts! Did we say charts already?!

### `--port`
- **Description**: The port to bind the webserver to. Defaults to 9242

### `--host`
- **Description**: The host to run the webserver on. Defaults to localhost. Use 0.0.0.0 if you want to listen to the whole world.

### `--rapl`
- **Description**: If you want to get the energy data from the CPU

### `--psys`
- **Description**: If you want to get the energy data for your machine

### `--rapl-sample-rate`
- **Description**: How often you want rapl and psys to get the data. Defaults to 500ms



## Weights for energy impact

When calculating the energy impact each value is multiplied with a `weight` these are different for each machine. You
can modify them in the `config.conf` or `/etc/powerletrics` file.

## FAQ and Tips:

### Terminal wraps because of long command line paramters
Execute this before starting the program

```
tput rmam
```

### Why is the memory value different to the value I see in top
Because we use `Total Virtual Memory` instead of `Resident Set Size`

### Why are there programs that do not show up in the list
Only programs that have run are listed as they are the only ones that have actually used something.

### Why don't you use psutil
Because it does the same things (yes we check) and is slower as it adds more overhead. We still 😍 psutil though.
