#!/usr/bin/env bash
set -euo pipefail

readonly pinned_commit=562bae590f194fb590beb5c65da44fc35ab9f64a
readonly qemu=/opt/qemu-build/qemu-system-x86_64
readonly source_tree=/opt/qemu-src
readonly layout_probe=/opt/qemu-build/cxl-layout-probe
readonly artifact_root=/lab/artifacts
readonly label="${LAB_RUN_LABEL:-run-manual}"
readonly run_dir="$artifact_root/$label"

if [[ ! -f /.dockerenv || "${LAB_CONTAINER:-}" != "1" ]]; then
    echo "refusing to run: the reproduction is permitted only inside its lab container" >&2
    exit 2
fi
if [[ ! "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]; then
    echo "invalid LAB_RUN_LABEL" >&2
    exit 2
fi
if [[ -e "$run_dir" || -e "$artifact_root/$label.tgz" ]]; then
    echo "refusing to overwrite existing evidence: $label" >&2
    exit 2
fi
if [[ ! -x "$qemu" || ! -x "$layout_probe" ]]; then
    echo "pinned QEMU build or layout probe is absent" >&2
    exit 2
fi

umask 077
mkdir -p "$run_dir"
qemu_pid=""

stop_qemu() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM "$qemu_pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            if ! kill -0 "$qemu_pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$qemu_pid" 2>/dev/null; then
            kill -KILL "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
    fi
}

finalize_evidence() {
    if [[ -d "$run_dir" ]]; then
        (
            cd "$run_dir"
            find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
                | LC_ALL=C sort -z \
                | xargs -0 -r sha256sum
        ) >"$run_dir/SHA256SUMS"
        tar --sparse --exclude='*.sock' -czf "$artifact_root/$label.tgz" \
            -C "$artifact_root" "$label"
        (
            cd "$artifact_root"
            sha256sum "$label.tgz"
        ) >"$artifact_root/$label.tgz.sha256"
    fi
}

on_exit() {
    local rc=$?
    trap - EXIT INT TERM
    stop_qemu
    if ! finalize_evidence; then
        echo "failed to finalize the evidence bundle" >&2
        if [[ "$rc" == "0" ]]; then
            rc=20
        fi
    fi
    exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

actual_commit="$(git -c "safe.directory=$source_tree" \
    -C "$source_tree" rev-parse HEAD)"
if [[ "$actual_commit" != "$pinned_commit" ]]; then
    echo "source commit mismatch: $actual_commit" >&2
    exit 3
fi

truncate -s 256M "$run_dir/mem0.img"
truncate -s 256M "$run_dir/lsa0.img"

python3 /lab/scripts/make-profile.py \
    --qemu "$qemu" \
    --layout-probe "$layout_probe" \
    --source "$source_tree" \
    --expected-commit "$pinned_commit" \
    --output "$run_dir/profile.json" \
    >"$run_dir/profile-derivation.txt"

printf '%s\n' "$actual_commit" >"$run_dir/source-commit.txt"
sha256sum "$qemu" >"$run_dir/qemu.sha256"
file "$qemu" >"$run_dir/qemu.file.txt"
readelf -h "$qemu" >"$run_dir/qemu-elf-header.txt"
"$qemu" --version >"$run_dir/qemu-version.txt"
cp /opt/qemu-build/meson-private/cmd_line.txt "$run_dir/build-options.txt"

qemu_args=(
    -machine "q35,cxl=on"
    -accel tcg
    -m 512M
    -device "pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=12"
    -device "cxl-rp,port=0,bus=cxl.1,id=root_port13,x-width=16"
    -device "cxl-type3,bus=root_port13,persistent-memdev=cxl-mem0,lsa=lsa0,id=pmem0"
    -object "memory-backend-file,id=cxl-mem0,mem-path=$run_dir/mem0.img,size=256M"
    -object "memory-backend-file,id=lsa0,mem-path=$run_dir/lsa0.img,size=256M"
    -display none
    -no-reboot
    -monitor "unix:$run_dir/mon.sock,server=on,wait=off"
    -qtest "unix:$run_dir/qt.sock,server=on,wait=off"
    -qtest-log "$run_dir/qtest-server.log"
)

printf '%q ' "$qemu" "${qemu_args[@]}" >"$run_dir/cmdline.txt"
printf '\n' >>"$run_dir/cmdline.txt"

(
    cd "$run_dir"
    exec "$qemu" "${qemu_args[@]}"
) >"$run_dir/qemu.stdout" 2>"$run_dir/qemu.stderr" &
qemu_pid=$!
printf '%s\n' "$qemu_pid" >"$run_dir/qemu.pid"

for _ in $(seq 1 240); do
    if [[ -S "$run_dir/qt.sock" && -S "$run_dir/mon.sock" ]]; then
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
if [[ ! -S "$run_dir/qt.sock" || ! -S "$run_dir/mon.sock" ]]; then
    echo "QEMU qtest/monitor sockets did not become ready" >&2
    sed -n '1,160p' "$run_dir/qemu.stderr" >&2
    exit 4
fi

cp "/proc/$qemu_pid/maps" "$run_dir/qemu-maps.txt"

set +e
python3 /lab/poc/cxl_mailbox_rce.py \
    --run-dir "$run_dir" \
    --profile "$run_dir/profile.json"
driver_rc=$?
set -e
printf '%s\n' "$driver_rc" >"$run_dir/driver.rc"

for _ in $(seq 1 40); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

process_replaced_or_exited=0
qemu_wait_rc=255
if ! kill -0 "$qemu_pid" 2>/dev/null; then
    process_replaced_or_exited=1
    set +e
    wait "$qemu_pid"
    qemu_wait_rc=$?
    set -e
fi
printf 'QEMU_PROCESS_REPLACED_OR_EXITED=%s\n' \
    "$process_replaced_or_exited" >"$run_dir/liveness.txt"
printf '%s\n' "$qemu_wait_rc" >"$run_dir/qemu.wait.rc"

if grep -Eq '^uid=[0-9]+' "$run_dir/qemu.stdout"; then
    identity_marker=1
else
    identity_marker=0
fi

if python3 - "$run_dir/driver-result.json" "$run_dir/profile.json" \
        "$run_dir/qemu.stdout" "$driver_rc" "$process_replaced_or_exited" \
        "$identity_marker" <<'PY'
import json
import pathlib
import sys

driver_path, profile_path, stdout_path = map(pathlib.Path, sys.argv[1:4])
driver_rc, process_replaced, marker = map(int, sys.argv[4:7])
driver = json.loads(driver_path.read_text()) if driver_path.is_file() else {}
profile = json.loads(profile_path.read_text())
stdout = stdout_path.read_text(errors="replace") if stdout_path.is_file() else ""
driver_proof = bool(
    driver.get("qemu_process_replacement_proven")
    or driver.get("host_process_replacement_proven")
)
proof = bool(
    driver_rc == 0
    and process_replaced == 1
    and marker == 1
    and driver.get("qtest_connection_closed") is True
    and driver_proof
)
summary = {
    "schema": "qemu-cxl-mailbox-rce-run/v1",
    "finding_chain": ["C25-f", "C32-a"],
    "scope": "QEMU process inside an unprivileged, networkless Docker container",
    "qemu_commit": profile["qemu_commit"],
    "qemu_sha256": profile["qemu_sha256"],
    "build_profile": profile["build_profile"],
    "driver_exit_code": driver_rc,
    "qtest_connection_closed": driver.get("qtest_connection_closed") is True,
    "qemu_process_replaced_or_exited": process_replaced == 1,
    "identity_output": stdout[:4096],
    "container_qemu_process_execution_proven": proof,
    "outer_docker_host_escape_proven": False,
}
pathlib.Path(driver_path.parent, "run-result.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(summary, indent=2, sort_keys=True))
raise SystemExit(0 if proof else 1)
PY
then
    proof=1
else
    proof=0
fi

{
    printf 'CONTAINER_QEMU_PROCESS_EXECUTION_PROVEN=%s\n' "$proof"
    printf 'OUTER_DOCKER_HOST_ESCAPE_PROVEN=0\n'
    printf 'EXECUTION_SCOPE=docker-contained-qemu-process\n'
} >"$run_dir/proof-status.txt"

if [[ "$proof" != "1" ]]; then
    echo "reproduction did not satisfy all execution assertions" >&2
    exit 10
fi

echo "QEMU process execution reproduced inside the lab container."
echo "No Docker-host escape was attempted or proven."
