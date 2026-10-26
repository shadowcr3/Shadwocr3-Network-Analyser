# Safety, privacy and limits

## Safe-use statement

Only scan networks and devices you own or have explicit written permission to assess. Unauthorised
scanning may be illegal and can disrupt services. The application is built so that the safe
path is the default; there is intentionally **no** "unrestricted" mode.

## What the application enforces

| Control | Behaviour |
|---|---|
| Scope allowlist | Only 10/8, 172.16/12, 192.168/16, loopback and link-local IPv4; hostnames and IPv6 rejected |
| Strict targets | Host bits must be zero (`192.168.1.5/24` is refused, never widened); no option-like input |
| Size cap | At most 256 addresses per scan |
| Authorisation | Required confirmation for every scan; recorded in the audit log and with the saved scan |
| Impact confirmation | More than 64 addresses, or `services` above 16, needs explicit confirmation; enforced in the core, not just the UI |
| Concurrency and cooldown | One scan at a time per process, 2 s cooldown afterwards |
| Probe limits | Nmap runs with `--max-rate 250` and `--max-retries 2`; no retry loops in the app |
| Fixed profiles | Users never supply raw Nmap flags; commands are argument lists, never shell strings |
| Timeouts and cancel | Hard timeout (10 to 3600 s); cancel and Ctrl+C kill the whole process tree |
| Audit-first | If the audit log cannot be written, no scan starts |
| Untrusted output | Nmap XML parsed with `defusedxml`; output size capped; control characters stripped |
| Honest results | Partial scans are labelled incomplete; "no hosts" never claims the network is empty |

## Audit trail

Every request, refusal, start, cancel, completion, failure, export, deletion and prune is
recorded with a UTC timestamp and job ID in an append-only table (triggers reject UPDATE and
DELETE). Scans that started but never finished are reported as interrupted on the next launch
and are **never restarted automatically**. Limit: someone with write access to the database file
can still alter it. The log records what the application did; it is not forensic-grade.

## Privacy and retention

Everything stays local. Original Nmap output is stored compressed with its SHA-256 and verified
on read. Nothing is deleted automatically: use the GUI's Delete, or
`shadowcr3-na history prune --keep N --yes`. Audit entries are kept when scans are deleted. PDF and
CSV reports include network details; the GUI asks before exporting and records each report's SHA-256.
Log files are rotated (1 MB x 3), structured and redacted for common secret patterns.

## Not covered in v0.1

- No cross-process scan lock; no restricted environment for the Nmap child process
- Hostname resolution by Nmap uses your system resolver
- The app cannot verify that you are authorised
- Unprivileged scans see less; elevated scans need the whole app elevated
