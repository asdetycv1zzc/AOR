#!/bin/sh
set -eu

fail() {
  echo "AOR sandbox preflight failed: $*" >&2
  exit 1
}

engine_endpoint=${AOR_SANDBOX_ENGINE_ENDPOINT:-}
image_reference=${AOR_SANDBOX_IMAGE_REFERENCE:-}
runtime_name=${AOR_SANDBOX_RUNTIME:-}
seccomp_profile=${AOR_SANDBOX_SECCOMP_PROFILE:-}
mandatory_policy=${AOR_SANDBOX_MANDATORY_POLICY:-}

case "$engine_endpoint" in
  unix:///*) ;;
  *) fail "AOR_SANDBOX_ENGINE_ENDPOINT must be an absolute unix endpoint" ;;
esac
if [ "$engine_endpoint" = "unix:///var/run/docker.sock" ]; then
  fail "the rootful host Docker socket is forbidden; configure a dedicated rootless engine socket"
fi
engine_socket=${engine_endpoint#unix://}
if [ ! -S "$engine_socket" ]; then
  fail "rootless engine socket is not mounted at $engine_socket"
fi
if [ "$(id -u)" = "0" ]; then
  fail "preflight and worker must run as the non-root owner of the rootless engine socket"
fi

case "$image_reference" in
  *@sha256:*) ;;
  *) fail "AOR_SANDBOX_IMAGE_REFERENCE must contain an immutable sha256 manifest digest" ;;
esac
image_digest=${image_reference##*@}
if [ "${#image_digest}" -ne 71 ]; then
  fail "sandbox image digest must be sha256 plus 64 lowercase hexadecimal characters"
fi
case "${image_digest#sha256:}" in
  *[!0-9a-f]*) fail "sandbox image digest must use lowercase hexadecimal characters" ;;
esac
if [ -z "$runtime_name" ]; then
  fail "AOR_SANDBOX_RUNTIME is required"
fi
if [ -z "$seccomp_profile" ] || [ "$seccomp_profile" = "unconfined" ]; then
  fail "an enforcing seccomp profile is required"
fi
case "$mandatory_policy" in
  apparmor=*|label=type:*) ;;
  *) fail "AOR_SANDBOX_MANDATORY_POLICY must select AppArmor or SELinux" ;;
esac
case "$mandatory_policy" in
  *unconfined*) fail "an unconfined mandatory access-control policy is forbidden" ;;
esac

engine_info=$(docker --host "$engine_endpoint" info --format '{{.OSType}}|{{.CgroupVersion}}|{{.DefaultRuntime}}|{{json .SecurityOptions}}|{{.MemoryLimit}}|{{.PidsLimit}}|{{.CPUCfsQuota}}') || fail "cannot query the configured OCI engine"
old_ifs=$IFS
IFS='|'
set -- $engine_info
IFS=$old_ifs
if [ "$#" -ne 7 ]; then
  fail "OCI engine returned an incomplete capability report"
fi
if [ "$1" != "linux" ]; then
  fail "OCI engine must report Linux"
fi
if [ "$2" != "2" ]; then
  fail "OCI engine must use cgroups v2"
fi
if [ "$3" != "$runtime_name" ]; then
  fail "OCI engine default runtime does not match AOR_SANDBOX_RUNTIME"
fi
case "$4" in
  *rootless*) ;;
  *) fail "OCI engine must report rootless mode" ;;
esac
case "$mandatory_policy" in
  apparmor=*)
    case "$4" in
      *apparmor*) ;;
      *) fail "rootless OCI engine does not report AppArmor; load deploy/compose/aor-sandbox.apparmor on the host" ;;
    esac
    ;;
  label=type:*)
    case "$4" in
      *selinux*) ;;
      *) fail "rootless OCI engine does not report SELinux" ;;
    esac
    ;;
esac
if [ "$5" != "true" ] || [ "$6" != "true" ] || [ "$7" != "true" ]; then
  fail "rootless OCI engine must enforce memory, PID, and CPU limits"
fi

docker --host "$engine_endpoint" image pull "$image_reference" >/dev/null || fail "cannot pull the pinned sandbox runtime image into the configured rootless engine"
repo_digests=$(docker --host "$engine_endpoint" image inspect "$image_reference" --format '{{json .RepoDigests}}') || fail "cannot inspect the pinned sandbox runtime image"
case "$repo_digests" in
  *"@$image_digest"*) ;;
  *) fail "installed sandbox runtime image does not match its configured manifest digest" ;;
esac

probe_id=
cleanup() {
  if [ -n "$probe_id" ]; then
    docker --host "$engine_endpoint" rm --force --volumes "$probe_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

probe_id=$(docker --host "$engine_endpoint" create \
  --read-only \
  --user 65532:65532 \
  --init \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --security-opt "seccomp=$seccomp_profile" \
  --security-opt "$mandatory_policy" \
  --pids-limit 32 \
  --memory 134217728 \
  --cpus 0.25 \
  --network none \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --tmpfs /workspace:rw,nosuid,nodev,size=16777216 \
  --workdir /workspace \
  "$image_reference" go version) || fail "cannot create a container with the required AOR security profile"

probe_security=$(docker --host "$engine_endpoint" inspect "$probe_id" --format '{{json .HostConfig.SecurityOpt}}') || fail "cannot inspect the sandbox preflight container"
case "$probe_security" in
  *no-new-privileges*"seccomp=$seccomp_profile"*"$mandatory_policy"*) ;;
  *) fail "OCI engine did not retain the required security options" ;;
esac
probe_state=$(docker --host "$engine_endpoint" inspect "$probe_id" --format '{{.Config.User}}|{{.Config.WorkingDir}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{json .HostConfig.CapDrop}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}') || fail "cannot inspect sandbox resource controls"
case "$probe_state" in
  '65532:65532|/workspace|true|false|none||["ALL"]|32|134217728|250000000') ;;
  *) fail "OCI engine changed or omitted required sandbox isolation controls" ;;
esac
docker --host "$engine_endpoint" start --attach "$probe_id" >/dev/null || fail "sandbox preflight container did not execute successfully"

echo "AOR sandbox preflight passed: rootless Linux CONTAINER backend with cgroups v2, seccomp, and mandatory access control"
