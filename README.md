# LogWatch

`LogWatch` is a defensive cybersecurity tool written in C for analyzing SSH authentication logs.

It detects failed login attempts, groups them by source IP address, and flags addresses that may be performing a brute-force attack.

The tool is read-only. It does not connect to other systems, block IP addresses, or modify log files.

## Features

- Parses OpenSSH failed-password entries.
- Extracts the attempted username and source IP address.
- Counts failed attempts for each IP address.
- Detects repeated attempts inside a configurable line window.
- Parses syslog timestamps and supports a time-based detection window.
- Prints an alert when an IP reaches the configured threshold.
- Supports whitelist and blacklist files without changing the log or firewall.
- Follows a growing log file in real time with `-f`.
- Emits JSON Lines events for Splunk, ELK, and the web dashboard.

## Project files

- `logwatch.c`: C source code.
- `test_logwatch.c`: Unit tests for parsing, timestamps, and IP lists.
- `README.md`: Project documentation.
- `periodic-table-hacker.html`: Browser dashboard for JSONL events.

## Requirements

- Linux, macOS, or another Unix-like environment.
- A C compiler such as GCC, Clang, or `cc`.
- An SSH authentication log to analyze.

## Build the project

Open a terminal in the project directory and run:

```sh
cc -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror logwatch.c -o logwatch
```

This creates an executable named `logwatch`.

## Run the analyzer

```sh
./logwatch /var/log/auth.log
```

If the log file requires administrator permissions, run:

```sh
sudo ./logwatch /var/log/auth.log
```

## Configure detection

The default configuration flags an IP after 5 failed attempts within 100 log lines.

Use `-t` to change the threshold, `-w` for the line fallback window, and `-s` for a timestamp window:

```sh
./logwatch /var/log/auth.log -t 10 -w 200
./logwatch /var/log/auth.log -t 10 -s 600
```

- `-t 10`: alert after 10 failed attempts.
- `-w 200`: count attempts within 200 log lines.
- `-s 600`: count attempts within 600 seconds when syslog timestamps are available.

## Live and SIEM output

Follow a growing log with `tail -f` behavior:

```sh
./logwatch /var/log/auth.log -f -j -t 5 -s 300
```

`-j` emits one JSON object per line (`alert`, `blocked`, or `summary`), which can be piped to a collector. IP list files contain one address per line; blank lines and `#` comments are ignored:

```sh
./logwatch /var/log/auth.log -W whitelist.txt -B blacklist.txt
```

The blacklist is an application-level block/report only; LogWatch never changes firewall rules. Open `periodic-table-hacker.html` in a browser, choose the JSONL file produced by a non-following run, and press `LOAD JSONL` to view the event dashboard.

For example, save the events for the dashboard or a collector:

```sh
./logwatch /var/log/auth.log -j -t 5 -s 300 > events.jsonl
```

## Test with a sample log

If your system does not have `/var/log/auth.log`, create a test file:

```sh
printf '%s\n' \
'Jan 01 00:00:01 host sshd: Failed password for admin from 203.0.113.9 port 22 ssh2' \
'Jan 01 00:00:02 host sshd: Failed password for root from 203.0.113.9 port 22 ssh2' \
'Jan 01 00:00:03 host sshd: Failed password for test from 203.0.113.9 port 22 ssh2' \
'Jan 01 00:00:04 host sshd: Failed password for guest from 203.0.113.9 port 22 ssh2' \
'Jan 01 00:00:05 host sshd: Failed password for user from 203.0.113.9 port 22 ssh2' > sample.log
```

Then run:

```sh
./logwatch sample.log
```

## Understanding the output

An alert looks like this in normal output:

```text
[ALERT] 203.0.113.9 reached 5 failed attempts
```

This means that the same IP address reached the configured threshold of failed login attempts.

With `-f`, existing lines are processed first and the command then waits for new lines. Press `Ctrl+C` to stop it; the final summary is printed only for a normal, non-following run.

The address `203.0.113.9` is reserved for documentation and is only used in the sample data.

## Supported log format

The current version looks for OpenSSH lines containing this pattern:

```text
Failed password for <user> from <ip>
```

## Unit tests

Run the parser, timestamp-window, and IP-list tests:

```sh
cc -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror test_logwatch.c -o test_logwatch
./test_logwatch
```