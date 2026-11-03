#!/usr/bin/env bash
# run-isolated.sh — run an untrusted command (e.g. LLM-generated code) in a
# locked-down container: no network, read-only root, no capabilities,
# unprivileged user, bounded pids/memory/cpu, noexec /tmp.
#
#   TV_SANDBOX_IMAGE=python:3.12-slim@sha256:<digest> \
#     run-isolated.sh [--mount DIR] [--rw] -- python3 -c "$code"
#   printf '%s' "$code" | run-isolated.sh -i -- python3 -
#
# Env: TV_SANDBOX_IMAGE (required; pin by digest), TV_SANDBOX_RUNTIME
# (docker|podman, default docker), TV_SANDBOX_MEMORY (512m),
# TV_SANDBOX_CPUS (1), TV_SANDBOX_PIDS (128).
# `toolchain-verify exec-lint` treats calls to run-isolated as isolated.
set -euo pipefail

die() { echo "run-isolated: $*" >&2; exit 2; }

runtime=${TV_SANDBOX_RUNTIME:-docker}
case $runtime in docker | podman) ;; *) die "TV_SANDBOX_RUNTIME must be docker or podman" ;; esac
image=${TV_SANDBOX_IMAGE:-}
[ -n "$image" ] || die "set TV_SANDBOX_IMAGE (pin it by digest: name@sha256:...)"
case $image in
-*) die "image must not start with '-'" ;;
*@sha256:*) ;;
*) echo "run-isolated: warning: $image is not pinned by digest" >&2 ;;
esac
mem=${TV_SANDBOX_MEMORY:-512m}

mounts=()
stdin=()
mode=ro
workdir=/tmp
while [ $# -gt 0 ]; do
	case $1 in
	--mount)
		[ $# -ge 2 ] || die "--mount needs a directory"
		dir=$(cd -- "$2" 2>/dev/null && pwd -P) || die "no such directory: $2"
		case $dir in
		/ | /etc | /root | /boot | /proc | /sys | /dev | /run | /var/run | /var/lib/docker | "${HOME:-/nonexistent}") die "refusing to mount $dir" ;;
		*,* | *.sock) die "refusing to mount $dir" ;;
		esac
		mounts+=(--mount "type=bind,source=$dir,target=/work,MODE")
		workdir=/work
		shift 2
		;;
	--rw) mode=rw; shift ;;
	-i) stdin=(-i); shift ;;
	--) shift; break ;;
	*) break ;;
	esac
done
[ $# -gt 0 ] || die "no command given"
for i in "${!mounts[@]}"; do mounts[i]=${mounts[i]/,MODE/,$mode}; done

exec "$runtime" run --rm \
	--network none \
	--read-only \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--user 65534:65534 \
	--ipc none \
	--pids-limit "${TV_SANDBOX_PIDS:-128}" \
	--memory "$mem" --memory-swap "$mem" \
	--cpus "${TV_SANDBOX_CPUS:-1}" \
	--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
	--workdir "$workdir" \
	${mounts[@]+"${mounts[@]}"} ${stdin[@]+"${stdin[@]}"} \
	"$image" "$@"
