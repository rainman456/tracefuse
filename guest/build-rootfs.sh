#!/usr/bin/env bash
# Build guest/out/rootfs.ext4 + guest/out/vmlinux.
#
# Start from a Firecracker-compatible kernel and an Ubuntu ext4 image; do not
# write a distro builder. The kernel must be uncompressed (vmlinux) and built
# with at least:
#   CONFIG_DEBUG_INFO_BTF=y CONFIG_BPF_EVENTS=y CONFIG_BPF_SYSCALL=y
#   CONFIG_FTRACE=y CONFIG_NF_TABLES=y CONFIG_NF_TABLES_IPV4=y
#   CONFIG_CGROUPS=y CONFIG_MEMCG=y CONFIG_CGROUP_PIDS=y
#   CONFIG_SECCOMP=y CONFIG_SECCOMP_FILTER=y CONFIG_EXT4_FS=y
#   CONFIG_VIRTIO_BLK=y CONFIG_VIRTIO_NET=y
# See https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
#
# Usage:
#   BASE_ROOTFS=ubuntu.ext4 KERNEL=vmlinux ./guest/build-rootfs.sh
set -euo pipefail
: "${BASE_ROOTFS:?set BASE_ROOTFS to an ubuntu ext4 image}"
: "${KERNEL:?set KERNEL to an uncompressed vmlinux with BTF enabled}"
BASE_ROOTFS=$(cd "$(dirname "$BASE_ROOTFS")" && pwd)/$(basename "$BASE_ROOTFS")
KERNEL=$(cd "$(dirname "$KERNEL")" && pwd)/$(basename "$KERNEL")
cd "$(dirname "$0")"
OUT=out

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing host tool: $1" >&2; exit 1; }
}

[ -f "$BASE_ROOTFS" ] || { echo "BASE_ROOTFS not found: $BASE_ROOTFS" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "KERNEL not found: $KERNEL" >&2; exit 1; }

for tool in truncate resize2fs e2fsck mkfs.ext4 sudo file readelf; do
  need "$tool"
done
mkdir -p "$OUT"

# 1. Kernel: Firecracker needs an ELF vmlinux, and bpftrace needs BTF.
if ! file -b "$KERNEL" | grep -q 'ELF'; then
  echo "KERNEL is not an ELF vmlinux: $KERNEL" >&2
  exit 1
fi
if ! readelf -S "$KERNEL" 2>/dev/null | grep -q '\.BTF'; then
  echo "KERNEL has no .BTF section; bpftrace cannot attach (CONFIG_DEBUG_INFO_BTF=y)" >&2
  exit 1
fi
cp "$KERNEL" "$OUT/vmlinux"

# 2. Rootfs: grow to 2 GiB, but never shrink a larger base image.
cp "$BASE_ROOTFS" "$OUT/rootfs.ext4"
size=$(stat -c %s "$OUT/rootfs.ext4")
want=$((2 * 1024 * 1024 * 1024))
if [ "$size" -lt "$want" ]; then
  truncate -s "$want" "$OUT/rootfs.ext4"
  rc=0
  e2fsck -f -y "$OUT/rootfs.ext4" >/dev/null || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "e2fsck failed with exit code $rc" >&2
    exit 1
  fi
  resize2fs "$OUT/rootfs.ext4"
else
  echo "rootfs is already >= 2 GiB; leaving its size unchanged"
fi

# 3. Install runtime packages, then verify them inside the image.
MNT=$(mktemp -d)
cleanup() {
  sync
  sudo umount "$MNT/dev/pts" 2>/dev/null || true
  sudo umount "$MNT/dev" 2>/dev/null || true
  sudo umount "$MNT/proc" 2>/dev/null || true
  sudo umount "$MNT/sys" 2>/dev/null || true
  sudo umount "$MNT" 2>/dev/null || true
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT
sudo mount -o loop "$OUT/rootfs.ext4" "$MNT"
sudo mount --bind /dev "$MNT/dev"
sudo mount --bind /dev/pts "$MNT/dev/pts"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sys "$MNT/sys"

# Replace (not follow) resolv.conf: cloud images often symlink it.
sudo rm -f "$MNT/etc/resolv.conf"
sudo cp /etc/resolv.conf "$MNT/etc/resolv.conf"
sudo chroot "$MNT" /bin/sh -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  mkdir -p /var/cache/apt/archives/partial /var/lib/apt/lists/partial /var/log/apt
  touch /var/log/dpkg.log
  chown _apt:root /var/cache/apt/archives/partial /var/lib/apt/lists/partial
  chmod 700 /var/cache/apt/archives/partial /var/lib/apt/lists/partial
  apt-get update
  apt-get install -y --no-install-recommends \
    python3 python3-seccomp bpftrace nftables iproute2 ca-certificates curl
  apt-get clean
  rm -rf /var/lib/apt/lists/*
'

sudo mkdir -p "$MNT/opt/tracefuse"
sudo install -m 0644 observer.bt "$MNT/opt/tracefuse/observer.bt"
sudo install -m 0644 ../internal/sandbox/tracer.py "$MNT/opt/tracefuse/tracer.py"
sudo install -m 0755 tracefuse-init "$MNT/sbin/tracefuse-init"

sudo chroot "$MNT" /bin/sh -c '
  set -e
  python3 -c "import seccomp" 2>/dev/null || { echo "guest: python3-seccomp missing" >&2; exit 1; }
  command -v bpftrace >/dev/null 2>&1 || { echo "guest: bpftrace missing" >&2; exit 1; }
  command -v nft >/dev/null 2>&1 || { echo "guest: nft missing" >&2; exit 1; }
  command -v python3 >/dev/null 2>&1 || { echo "guest: python3 missing" >&2; exit 1; }
  test -x /sbin/tracefuse-init || { echo "guest: /sbin/tracefuse-init missing" >&2; exit 1; }
  test -r /opt/tracefuse/observer.bt || { echo "guest: observer.bt missing" >&2; exit 1; }
  test -r /opt/tracefuse/tracer.py || { echo "guest: tracer.py missing" >&2; exit 1; }
  echo "guest image OK: $(python3 --version 2>&1); $(bpftrace --version 2>&1 | head -n1)"
'

echo "built $OUT/rootfs.ext4 and $OUT/vmlinux"
