# LogWatch

`LogWatch` is a defensive cybersecurity tool written in C for analyzing SSH authentication logs.

It detects failed login attempts, groups them by source IP address, and flags addresses that may be performing a brute-force attack.

The tool is read-only. It does not connect to other systems, block IP addresses, or modify log files.

## Features

- Parses OpenSSH failed-password entries.
- Extracts the attempted username and source IP address.
- Counts failed attempts for each IP address.
- Detects repeated attempts inside a configurable line window.
- Prints an alert when an IP reaches the configured threshold.
- Prints a summary containing totals and log line ranges.

## Project files

- `logwatch.c`: C source code.
- `README.md`: Project documentation.

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

Use `-t` to change the threshold and `-w` to change the line window:

```sh
./logwatch /var/log/auth.log -t 10 -w 200
```

- `-t 10`: alert after 10 failed attempts.
- `-w 200`: count attempts within 200 log lines.

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

An alert looks like this:

```text
[ALERT] 203.0.113.9 reached 5 failed attempts within 100 log lines
```

This means that the same IP address reached the configured threshold of failed login attempts.

The address `203.0.113.9` is reserved for documentation and is only used in the sample data.

## Supported log format

The current version looks for OpenSSH lines containing this pattern:

```text
Failed password for <user> from <ip>
```

## Future improvements

- Use real timestamps instead of line counts for detection windows.
- Support real-time monitoring with `tail -f`.
- Add JSON output for SIEM integration.
- Add configurable detection rules.
- Add automated unit tests.
- Add a web dashboard for viewing alerts.