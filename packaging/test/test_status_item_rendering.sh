#!/usr/bin/env bash
# Requires an interactive macOS desktop and Screen Recording access.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
bundle="${scratch}/StatusRendering.app"
mkdir -p "${bundle}/Contents/MacOS"
sdk="${STATUS_ITEM_TEST_SDK:-$(xcrun --sdk macosx27.0 --show-sdk-path)}"
xcrun swiftc -parse-as-library -target "$(uname -m)-apple-macosx14.0" -sdk "${sdk}" \
  -Xclang-linker -isysroot -Xclang-linker "${sdk}" \
  "${root}/menubar/Sources/SecureAgentMenubar/StatusItemController.swift" \
  "${root}/packaging/test/status_item_rendering.swift" \
  -o "${bundle}/Contents/MacOS/StatusRendering"
python3 - "${bundle}" <<'PY'
import pathlib
import plistlib
import os
import selectors
import shutil
import subprocess
import sys
import uuid

bundle = pathlib.Path(sys.argv[1])
binary = bundle / "Contents/MacOS/StatusRendering"
(bundle / "Contents/Info.plist").write_bytes(plistlib.dumps({
    # Isolate the probe from prior runs' Control Center visibility preferences.
    "CFBundleIdentifier": "com.cavi-ai.status-rendering-regression." + uuid.uuid4().hex,
    "CFBundleName": "Status Rendering Regression",
    "CFBundleExecutable": binary.name,
    "CFBundlePackageType": "APPL",
    "CFBundleVersion": "1",
    "CFBundleShortVersionString": "1.0",
    "LSMinimumSystemVersion": "14.0",
    "LSUIElement": False,
}))
subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(bundle)], check=True)
def check_rendering(bundled):
    if bundled:
        output_path = bundle.parent / "probe-output"
        os.mkfifo(output_path)
        output = os.fdopen(os.open(output_path, os.O_RDONLY | os.O_NONBLOCK), "r")
        probe = subprocess.Popen(["/usr/bin/open", "-n", "-W", "--stdout", str(output_path), str(bundle)])
    else:
        control = bundle.parent / "UnbundledStatusRendering"
        shutil.copy2(binary, control)
        probe = subprocess.Popen([str(control)], stdout=subprocess.PIPE, text=True)
        output = probe.stdout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(output, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                raise RuntimeError("The status-item probe did not start")
            ready = output.readline().strip().split()
            if len(ready) != 2 or ready[0] != "CAPTURE":
                raise RuntimeError("The status-item probe did not start")
        captures = []
        for display in range(1, int(ready[1]) + 1):
            capture = bundle.parent / f"menu-bar-{display}.png"
            subprocess.run(["/usr/sbin/screencapture", "-x", "-D", str(display), str(capture)],
                           check=True, timeout=5)
            if not capture.exists():
                raise RuntimeError("Screen Recording access is required for the rendering regression")
            captures.append(capture)
        return subprocess.run([str(binary), *map(str, captures)], timeout=5).returncode
    finally:
        output.close()
        try:
            probe.wait(timeout=12)
        except subprocess.TimeoutExpired:
            probe.terminate()
            probe.wait(timeout=5)

# The same executable is the positive control for the marker and capture path.
print("Checking unbundled rendering control", flush=True)
if check_rendering(bundled=False):
    sys.exit("Rendering control failed: desktop capture cannot establish icon visibility")
print("Checking signed app-bundle rendering", flush=True)
sys.exit(check_rendering(bundled=True))
PY
