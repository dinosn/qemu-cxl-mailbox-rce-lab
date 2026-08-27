# QEMU CXL mailbox process-execution lab

> **Private security-research repository. Do not make this repository public,
> mirror it, or run it against systems you do not own or have explicit
> permission to test.**

This lab deterministically reproduces a composed CXL Type-3 mailbox issue in
QEMU at commit `562bae590f194fb590beb5c65da44fc35ab9f64a`
(`v11.1.0-648-g562bae590f`). An oversized `SET_LSA` first discloses a live QEMU
code pointer; an oversized `GET_LSA` then overwrites an inline CXL command
handler and dispatches through it. The safe demonstration target is the
Linux-lab call `execvp("/bin/id", NULL)` inside the disposable container. The
NULL second argument comes from dispatching command `0000h` with zero input
length; no caller-selected command is accepted.

## Result and scope

| Question | Status |
|---|---|
| Memory disclosure from the fixed 2,048-byte mailbox payload | Proven |
| Command-handler overwrite and controlled dispatch | Proven |
| Code execution in an optimized, PIE, non-ASAN QEMU process | Proven |
| Reproduction through qtest MMIO with TCG inside Docker | Included here |
| Delivery from a booted KVM guest | Not yet demonstrated |
| Escape from the Docker container to its outer host | Not demonstrated or claimed |
| Reachability in every QEMU deployment | Not claimed; a configured CXL Type-3 device with an LSA backend and mailbox access is required |

The owner-facing rating is **High in the validated scope, with a Critical
impact ceiling** if the same sequence is delivered by a booted, untrusted KVM
guest across a supported virtualization boundary. A qtest socket closing or a
process crash alone is not accepted as code execution: the lab also requires
the staged bytes to match and QEMU stdout to contain the `/bin/id` identity
record.

See [the finding](docs/FINDING.md) for the source-to-sink chain and
[the validation record](evidence/VALIDATION.md) for the historical evidence
handles and controls.

## Safety model

The dynamic test is intentionally narrow:

- QEMU runs in a disposable Docker container using TCG and qtest.
- No `/dev/kvm`, host device, disk image, or production workload is required.
- Runtime networking is disabled.
- QEMU's optional internal seccomp support is disabled in this exact build so
  the fixed `execvp()` marker can execute; Docker's isolation controls remain
  enabled. This matches the validated build profile and is a material lab
  precondition.
- The only execution target is the fixed path `/bin/id`; the lab does not
  accept a caller-supplied command.
- Generated logs, sockets, binaries, and receipts stay under the ignored
  `artifacts/` area and are not part of the source repository.
- The identity printed by the proof belongs to the QEMU process context inside
  the container. It is not evidence of container-host escape.

Docker is an isolation boundary with its own operational risk. Review the
compose file before running it, use a non-production workstation, and do not
add privileged mode, host PID/network namespaces, host devices, or broad host
mounts.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2
- Git
- Sufficient space and time to compile the pinned QEMU revision
- Network access during `./lab build` so the source revision and build
  dependencies can be fetched

The reproduction itself runs without network access.

## Run the lab

From the repository root:

```bash
./lab verify
./lab build
./lab test
./lab status
```

`verify` performs local source and repository checks without running the PoC.
`build` creates the pinned optimized QEMU image. `test` starts a fresh bounded
run and asserts the full disclosure-to-dispatch chain. `status` summarizes the
latest receipt.

A successful dynamic run establishes all of these conditions:

1. The baseline unassigned command `0000h` returns Unsupported.
2. A bounded disclosure returns the expected live handler class.
3. The derived PIE base is page-aligned and both symbol offsets match the
   profile extracted from the built QEMU ELF.
4. `/bin/id` and the derived `execvp@plt` address are read back exactly, and
   the final zero-length dispatch supplies a NULL second handler argument.
5. The final command replaces the QEMU process, closes qtest, and emits an
   identity line on QEMU stdout.
6. The machine-readable result marks the run successful only after the stdout
   assertion passes.

The packaged lab completed this full sequence in a fresh Docker validation on
2026-08-27. Its sanitized build and receipt handles are recorded in
[`evidence/VALIDATION.md`](evidence/VALIDATION.md); raw generated artifacts stay
outside Git.

Build-layout distances and symbol offsets are derived for the produced binary;
they are not assumed to be stable across compilers or configurations. The
historical optimized validation measured a 2,600-byte payload-to-primary-CCI
distance and a 2,616-byte final copy, but a new run must use its own measured
profile. The generated build options also preserve the explicit seccomp-disabled
lab configuration.

## Inspect and clean up

Generated evidence is written below `artifacts/` and should include a
machine-readable result, QEMU stdout/stderr, build/profile metadata, and a
checksum manifest. Treat generated evidence as sensitive even though the
demonstration command is fixed.

```bash
./lab status
./lab clean
```

`clean` removes the lab's runtime containers and networks. It deliberately
preserves the built image and generated evidence so an owner can inspect the
receipt after cleanup. Delete a reviewed artifact directory separately when
its retention period ends; generated artifacts remain ignored by Git.

## Private-repository handling

Keep GitHub visibility set to **Private**, grant access only to the review team,
and do not enable public forks or public issue disclosure. Before each push,
run `./lab verify` and inspect `git diff --cached`. This repository is intended
to contain source and sanitized documentation only; never commit generated
receipts, QEMU binaries, images, credentials, tokens, private target details,
or workstation paths.
