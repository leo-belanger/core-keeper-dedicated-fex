#!/usr/bin/env bash
# Execute inside the FEX image on native ARM64. No game or save access.
set -Eeuxo pipefail
test "$(dpkg --print-architecture)" = arm64
test "${COREKEEPER_RUNTIME}" = fex
test -x /usr/bin/FEX
dpkg-query -W fex-emu-armv8.0
test -d "${FEX_ROOTFS}/usr/lib/x86_64-linux-gnu"
test -s /opt/fex-rootfs-source.json
gosu steam /usr/bin/FEX "${FEX_ROOTFS}/usr/bin/true"
gosu steam /usr/bin/FEX "${FEX_ROOTFS}/usr/bin/printf" 'FEX_GUEST_SMOKE_PASS\n'
