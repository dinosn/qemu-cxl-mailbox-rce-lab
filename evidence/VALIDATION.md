# Sanitized validation record

This is a source-only, sanitized record of the validation completed on
2026-08-27. Raw receipts and compiled binaries are intentionally not committed
because they contain environment-specific metadata and are not required to run
this lab.

## Target identity

| Field | Value |
|---|---|
| QEMU revision | `562bae590f194fb590beb5c65da44fc35ab9f64a` |
| Git describe | `v11.1.0-648-g562bae590f` |
| Optimized profile | `-O2`, PIE, full RELRO, non-ASAN, x86_64-softmmu |
| Optimized historical binary SHA-256 | `0bec55c687dc8a9b84ab006226103621423ca4bc3d52e245543cfc53bf950fa5` |
| ASAN/debug historical binary SHA-256 | `5250e3663eb1fe39abda44509c748e392a8412e0d93df5b1e8c69901653ed0e0` |

The binary hashes bind the original evidence to its exact builds. A fresh lab
build may have a different hash or layout because compiler, linker, and system
library versions affect the result; the source revision alone does not promise
a reproducible binary hash.

## Fresh repository-lab validation

The packaged lab was rebuilt and executed from source on 2026-08-27 using its
`linux/amd64` Docker profile. The fresh optimized QEMU binary had SHA-256
`b3b626f0460025a8d058283e5b244143efbb943695213dbab1e8d117a225920b`.
The build independently measured the 2,600-byte payload-to-primary-CCI distance,
located `cmd_infostat_bg_op_abort` at ELF offset `0x4d34a0`, and located
`execvp@plt` at `0x345070`.

The run satisfied every acceptance signal: baseline Unsupported, live handler
disclosure, page-aligned PIE derivation, exact staged-entry readback, zero-length
final dispatch, qtest connection closure, process replacement, and an identity
line of `uid=501 gid=20(dialout) groups=20(dialout)` on QEMU stdout. The
machine-readable result set `container_qemu_process_execution_proven: true` and
`outer_docker_host_escape_proven: false`.

Fresh evidence handles:

| Evidence object | SHA-256 |
|---|---|
| Checksummed run archive | `a7599f84821f9725d80caa853f12aecc0ea5b7301f50b2095f15c2bdb597ddb4` |
| Machine-readable run result | `cffe4d8a7b577dfd6d5560553da19586e57e1e05ecf532cdb3e895eb12fce42b` |
| Detailed driver receipt | `af6ec127d36e173973762aa32748c837e625b656fcbeeddb7c47c0ce09e35a9d` |

The ignored archive remains local to the validation workstation; only these
sanitized handles are committed.

## Optimized proof result

The independent optimized run began at `2026-08-27T13:41:54Z` and completed at
`2026-08-27T13:42:00Z`.

| Assertion | Observed result |
|---|---|
| Decoded mailbox payload maximum | 2,048 bytes |
| Declared disclosure `SET_LSA` length | 3,000 bytes |
| Bounded disclosure read | 64 bytes |
| Disclosed symbol class | `cmd_infostat_bg_op_abort` |
| Known-handler binary offset | `0x04d2c70` |
| Derived PIE base | Page-aligned |
| Selected execution target | `execvp@plt` |
| Target binary offset | `0x0347150` |
| Measured payload-to-primary-CCI distance | 2,600 bytes |
| Final `GET_LSA` length | 2,616 bytes |
| Staged pathname | `/bin/id\0` |
| LSA offset-zero staging control | Exact zero qword |
| Final command input length | Zero, causing QEMU to pass NULL as handler argument two (`argv`) |
| Pre-dispatch staged-byte check | Exact match |
| Dispatch transport result | qtest peer closed the connection |
| Independent execution marker | QEMU stdout contained `uid=0(root) gid=0(root) groups=0(root)` |
| Process replacement | Proven |
| Machine-readable result | `ok: true` |

The identity is that of the QEMU process inside the validation container. It is
not evidence of code execution in the outer Docker host.

## Control matrix

| Control | Result | Meaning |
|---|---|---|
| Baseline command `0000h` | Unsupported | Establishes behavior before corruption |
| Exact 2,048-byte `GET_LSA` | Normal completion; no ASAN finding | Confirms the payload boundary |
| Oversized copy with zero handler | Unsupported; QEMU remained alive | Rules out socket activity alone as control flow |
| Invalid guest-authored handler marker | ASAN PC matched the marker | Proves exact handler control |
| Original valid handler restored | Distinctive handler return; QEMU alive | Proves controlled valid dispatch |
| ASAN `system@plt` run | Identity marker created; QEMU alive | First concrete command-execution proof |
| Optimized `execvp@plt` run | QEMU replaced; identity on stdout | Confirms the result without ASAN/debug instrumentation |

## Historical evidence handles

The following SHA-256 values refer to externally retained historical receipts;
the files themselves are deliberately excluded from this source repository.

| Evidence object | SHA-256 |
|---|---|
| Optimized execution archive | `7f945fa6e392163b1ec10f20a021acc4059dbb639d85e961e155c4b8602b4892` |
| Optimized machine-readable result | `bf923fbd800a02b54b496776664f51ca2343b958bd3c152319ff0de8db2f1eda` |
| Optimized QEMU stdout | `5ef391d886d04116cf84b584ae37ef136f83950ab69b7bfb2a6da7506f7b3a57` |
| Independent ASAN execution archive | `ddbd980185ed5e02580ee918e0baa20d29591bba58a2fe9749270542837654d6` |
| Reproduced ASAN execution archive | `f454bc389c3272cc7123f3462350dfba94e2164625c1b52ceef72687f8652536` |
| Exact 2,048-byte safe-boundary control | `ae45fa591bab8dc8caffef3116d46511bf1fdec3bd8e9b0b627b6e2fc7f8fb62` |
| Zero-handler differential control | `4b661afd4b26add4150614e60da5d3a20c2cc21dabdfe7090934cb16763ebbda` |
| Invalid-PC marker control | `24da52202929d7e406dc69566f5252d8cb2410ecb3eb7e183abacd4b6cc6e37c` |

## Evidence interpretation

The optimized archive hash, result hash, and stdout hash provide independent
handles for the original proof. They do not replace the raw receipts and do not
make this document self-authenticating. Re-run `./lab test` to produce a fresh,
locally verifiable receipt for the current container image and toolchain.

The lab's qtest harness drives the same CXL device-model MMIO path available to
a guest, but the validation did not boot a guest or use KVM. Accordingly, this
record proves QEMU-process execution through qtest/TCG and preserves booted
KVM guest delivery as an explicit open validation item.
