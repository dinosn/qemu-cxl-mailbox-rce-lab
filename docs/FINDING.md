# CXL mailbox length flaws compose into QEMU-process code execution

## Assessment

At QEMU commit `562bae590f194fb590beb5c65da44fc35ab9f64a`, two independently
dangerous CXL mailbox length-validation flaws compose into controlled execution
in the QEMU process:

1. `C25-f`: the mailbox input length can exceed the 2,048-byte inline payload,
   causing an out-of-bounds host read that `SET_LSA` persists and `GET_LSA`
   returns.
2. `C32-a`: `GET_LSA` can copy more than the fixed output payload can hold,
   reaching the adjacent primary `CXLCCI` command table and overwriting a
   handler pointer.

The chain was reproduced in both an ASAN/debug build and a separate optimized
`-O2`, PIE, full-RELRO, non-ASAN x86_64-softmmu build. The optimized proof
replaced QEMU with `/bin/id` through its imported `execvp@plt` entry and
captured the resulting identity on QEMU stdout.

**Severity:** High for the validated qtest/TCG device-model execution path,
with a Critical ceiling pending delivery of the same MMIO sequence from a
booted, untrusted KVM guest. This is not a demonstrated Docker-host escape.

Potential weakness classes are CWE-125 (out-of-bounds read) and CWE-787
(out-of-bounds write).

## Affected configuration and attacker prerequisites

The demonstrated path requires:

- a QEMU machine exposing a CXL Type-3 device;
- an LSA backend large enough for the requested operations;
- attacker access to the device's mailbox registers through its PCI BAR; and
- a vulnerable build whose inline device layout lets the oversized output
  reach the primary CCI table.

These are meaningful prerequisites. The issue is not reachable in a deployment
that does not expose this device configuration. The exact overwrite distance
and symbol offsets are build-specific, although the unsafe inline adjacency is
source-defined. The execution lab also builds QEMU without its optional internal
seccomp support so the fixed `execvp()` marker is not blocked; a production
deployment's sandbox policy must be assessed separately.

## Source-to-sink evidence

All line references below are bound to commit
`562bae590f194fb590beb5c65da44fc35ab9f64a` and may drift in later revisions.

### 1. Mailbox input over-read and disclosure (`C25-f`)

- `include/hw/cxl/cxl_device.h:383-387` exposes a 20-bit command `LENGTH`.
- `include/hw/cxl/cxl_device.h:81-88,402-403` establishes the actual payload
  capacity as 2,048 bytes beginning after the 32-byte register header.
- `hw/cxl/cxl-device-utils.c:193-210` extracts the untrusted length and calls
  `g_memdup2(pl, len_in)` before enforcing that payload capacity.
- `hw/cxl/cxl-mailbox-utils.c:2303-2332` lets variable-length `SET_LSA`
  persist `len_in - 8` bytes from the staging copy.
- A later bounded `GET_LSA` returns the persisted bytes, turning the host
  over-read into a disclosure channel.

The validated disclosure used a declared 3,000-byte `SET_LSA` while writing
only the legitimate 2,048 mailbox bytes. It persisted 952 bytes read from
adjacent QEMU memory. A bounded 64-byte `GET_LSA` recovered a live
`cmd_infostat_bg_op_abort` handler pointer. Subtracting the exact binary symbol
offset produced a page-aligned PIE base.

### 2. Mailbox output overwrite (`C32-a`)

- `hw/cxl/cxl-mailbox-utils.c:2274-2300` checks the requested `GET_LSA` range
  only against the LSA backend size, then asks the backend to copy the full
  length into `payload_out`.
- `hw/mem/cxl_type3.c:1394-1410` performs the backend `memcpy` without knowing
  the 2,048-byte destination capacity.
- `include/hw/cxl/cxl_device.h:705-726` places `CXLDeviceState` and the primary
  `CXLCCI` inline within `CXLType3Dev`.
- `include/hw/cxl/cxl_device.h:145-180` places `cxl_cmd_set[256][256]` first in
  `CXLCCI`; each command entry includes a name and handler pointer.
- `hw/cxl/cxl-mailbox-utils.c:4599-4648` reads the selected handler from that
  table and invokes it.
- `hw/mem/cxl_type3.c:918-927` exposes the device register block through a PCI
  BAR, connecting mailbox access to the device-model path.

In the historical optimized build, the measured distance from the mailbox
payload to the primary CCI was 2,600 bytes. A 2,616-byte `GET_LSA` therefore
installed 16 attacker-staged bytes over command entry `0000h`: `/bin/id\0` in
the entry's first eight bytes and the live `execvp@plt` address in its handler
slot.

### 3. Controlled dispatch

`cxl_process_cci_message()` invokes a handler with the address of the selected
command entry as argument one and `pl_in` as argument two. The final `0000h`
dispatch declares zero input bytes, so `mailbox_reg_write()` leaves its
`pl_in_copy` NULL and passes that NULL value as argument two. After the
overwrite:

- argument one points at bytes beginning with `/bin/id\0`, satisfying
  `execvp()`'s pathname parameter;
- the zero-length dispatch supplies NULL as `execvp()`'s `argv` argument; and
- the overwritten handler points to the live optimized binary's
  `execvp@plt`.

The LSA's first qword was also read back as zero before dispatch. That is a
useful staging control, but it is not the source of the NULL pointer passed by
the zero-length command path.

Dispatch replaced QEMU with `/bin/id`. The qtest connection closed as a
consequence, and the identity line on QEMU stdout provided the independent
execution marker. Socket closure by itself is not treated as proof.

## Dynamic controls

The validation used differential and positive controls:

- An exact 2,048-byte `GET_LSA` completed without an ASAN error.
- The same oversized overwrite with a zero handler left command `0000h`
  Unsupported and QEMU alive.
- A guest-authored invalid handler marker produced an ASAN fault at the exact
  marker program counter.
- Installing the original valid handler changed `0000h` to its distinctive
  `Request Abort Not Supported (0x20)` result while QEMU stayed alive.
- An ASAN build dispatched through `system@plt`, created an identity marker,
  and remained alive.
- The separate optimized non-ASAN PIE build dispatched through `execvp@plt`,
  replaced QEMU, and emitted the identity record.

## Impact boundaries

| Claim | Evidence status |
|---|---|
| Confidentiality impact in the QEMU process | Proven live pointer disclosure |
| Integrity/control-flow impact in the QEMU process | Proven handler overwrite and controlled dispatch |
| Arbitrary operator-selected command execution | Deliberately not implemented by this lab; the proof target is fixed to `/bin/id` |
| Booted guest-to-QEMU escape over KVM | Plausible next step, not yet demonstrated |
| Escape from the lab container to its outer host | Not demonstrated; no such mechanism is part of the chain |
| Persistence or lateral movement | Not attempted or claimed |

The original optimized proof ran QEMU as the container's root user, so its
identity output reflects the container/QEMU execution context. A production
QEMU process may run as an unprivileged service account or under additional
sandboxing.

## Remediation

Treat both length flaws as one security patch:

1. Before `g_memdup2()`, reject any mailbox input length greater than the
   configured payload capacity (`cci->payload_max` or the appropriate central
   maximum).
2. In `cmd_ccls_get_lsa()`, reject a requested response length greater than the
   output payload capacity before invoking the backend copy.
3. Replace addition-based range checks with overflow-safe forms such as
   `offset <= size && length <= size - offset`.
4. Pass destination capacity into mailbox handlers or use a bounded output
   abstraction so a backend cannot exceed the register payload.
5. Add qtests for 2,048- and 2,049-byte input/output boundaries, oversized
   `SET_LSA`, bounded `GET_LSA`, and the composed regression sequence.

Defense in depth should include an unprivileged QEMU service account, a minimal
device model, process sandboxing, and QEMU's Linux seccomp policy. A deployment
with `spawn=deny` can block these particular process-spawning targets, but that
does not repair the disclosure or command-handler overwrite.

## Remaining validation work

The highest-value next step is a guest-side driver that emits the same mailbox
MMIO sequence from a booted KVM guest against the optimized vulnerable build.
That test should preserve the same acceptance bar: a fresh leak, build-bound
PIE derivation, exact staged-byte readback, a concrete execution marker, and
explicit separation between QEMU-process execution and any outer sandbox or
container boundary.
