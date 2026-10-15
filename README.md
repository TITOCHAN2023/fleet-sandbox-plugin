# Fleet Sandbox Plugin

An MIT-licensed Fleet task plugin that runs one command inside a native sandbox on the device. The workspace stays on that machine. Fleet Hub still only authenticates the account and carries the generic task ticket.

`fleet.sandbox` is not part of the Fleet Agent binary. The Agent installs this program, checks the release SHA-256, and opens its page through the generic plugin host.

## Actions

`ui` returns the device page. `probe`, `config`, `inspect`, `diff`, and `list` are reads. `configure`, `run`, `export`, `encrypt_storage`, and `discard` are writes and still follow the device permit.

## Build

```bash
go test ./...
sh scripts/build.sh
```

`scripts/build.sh` writes six stripped release binaries and `dist/manifest.json`. A local device can install that directory with `fleet plugins install-local`. The manifest URLs point at the `v0.1.0` GitHub release; the checksums are of the binaries just built.

## What this version actually isolates

- Linux: Landlock, seccomp, and user/PID/network namespaces when the kernel provides them. File writes stay in the private workspace. A missing `strace` is reported as a coverage gap.
- Windows: AppContainer with no network capabilities, plus a Job Object. This tree compiles. It has not been run on a Windows machine.
- macOS: an experimental Seatbelt launcher. There is no signed App Sandbox helper and no Endpoint Security or Network Extension entitlement in this repository.

`copy` is the default workspace. Linux `demand` is the on-demand merged view. macOS and Windows demand mounts are not accepted. The plugin does not inherit Fleet or model credentials.

`filelock` and `vault` in this repository are the copies the plugin links. They have to stay compatible with the device vault protocol used by Fleet Agent.

## License

MIT
