# Local Network Port Scanner

An educational Python TCP port scanner for authorized defensive testing. It checks selected ports on a target host and reports open ports with typical service names.

## Safety Scope

The tool allows only `localhost` and loopback addresses by default. A non-loopback target requires the explicit `--allow-authorized-target` flag and must belong to you or be covered by written permission. Never scan public IPs, school or company networks, or other people's devices without authorization.

## Requirements

- Python 3.8 or later
- No external packages

## Run on Localhost

```bash
python3 port_scanner.py
```

This checks a small set of common ports: 22, 80, 443, and 8080.

To specify ports:

```bash
python3 port_scanner.py 127.0.0.1 --ports 22 80-82 8080
```

The range limit is intentionally small for this educational project.

## Output

The scanner reports open TCP ports and a typical service associated with each port. A service label is only a common convention; the actual service should be verified using authorized system administration tools.

## Why Open Ports Matter

An open port means a TCP service is reachable. It is not automatically a vulnerability, but every exposed service increases the system's attack surface. Administrators should identify the service, keep it updated, require appropriate authentication, restrict network access, and disable unnecessary services.

## Demo

A safe demo can run a temporary HTTP server on `localhost`, scan only port 8080, observe the open result, stop the server, and run the scan again to observe that the port is no longer open. Use a test server and do not scan any external host.

## Limitations

This is a simple TCP connect scanner. It does not perform stealth scanning, service fingerprinting, vulnerability exploitation, UDP scanning, or OS detection. A closed/filtered result can also be caused by a firewall or timeout.
