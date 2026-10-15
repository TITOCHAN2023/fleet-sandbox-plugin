#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist=${FLEET_PLUGIN_DIST:-"$root/dist"}
mkdir -p "$dist"

for target in \
  darwin/amd64 darwin/arm64 \
  linux/amd64 linux/arm64 \
  windows/amd64 windows/arm64
do
  goos=${target%/*}
  goarch=${target#*/}
  suffix=""
  if [ "$goos" = "windows" ]; then suffix=".exe"; fi
  output="$dist/fleet-sandbox-plugin-$goos-$goarch$suffix"
  (cd "$root" && GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o "$output" .)
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dist" && sha256sum fleet-sandbox-plugin-*) > "$dist/checksums.txt"
else
  (cd "$dist" && shasum -a 256 fleet-sandbox-plugin-*) > "$dist/checksums.txt"
fi

python3 - "$dist" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
actions = ["ui", "probe", "config", "configure", "run", "inspect", "diff", "list", "export", "encrypt_storage", "discard"]
specs = {action: {"runtime": "task"} for action in actions}
artifacts = []
for target_os in ["darwin", "linux", "windows"]:
    for arch in ["amd64", "arm64"]:
        suffix = ".exe" if target_os == "windows" else ""
        filename = f"fleet-sandbox-plugin-{target_os}-{arch}{suffix}"
        digest = hashlib.sha256((root / filename).read_bytes()).hexdigest()
        artifacts.append({
            "os": target_os,
            "arch": arch,
            "url": f"https://github.com/TITOCHAN2023/fleet-sandbox-plugin/releases/download/v0.1.0/{filename}",
            "sha256": digest,
            "entrypoint": "fleet-sandbox-plugin.exe" if target_os == "windows" else "fleet-sandbox-plugin",
        })
manifest = {
    "schema_version": 1,
    "id": "fleet.sandbox",
    "name": "Fleet Sandbox",
    "version": "0.1.0",
    "publisher": "Fleet Official",
    "license": "MIT",
    "repository": "https://github.com/TITOCHAN2023/fleet-sandbox-plugin",
    "runtime": "task",
    "actions": actions,
    "approval_actions": [],
    "action_specs": specs,
    "ui": {
        "title": "Fleet Sandbox",
        "page_action": "ui",
        "read_actions": ["probe", "config", "inspect", "diff", "list"],
        "write_actions": ["configure", "run", "export", "encrypt_storage", "discard"],
    },
    "artifacts": artifacts,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
