# Release process

This document describes the CI policy and how release artifacts are produced
for IC-SYNC.

## CI policy

Continuous integration is defined in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

- **Triggers:** every `push` and every `pull_request`.
- **Runner:** `ubuntu-latest`, Rust **stable** with `rustfmt` and `clippy`
  installed, plus the Linux system libraries needed by `iced` and `tray-icon`.
- **Checks (all must pass):**

  ```sh
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  cargo build --workspace --release
  ```

  `clippy` is run with `-D warnings`, so any warning is a build failure.

- No credentials, sessions, tokens or account data are used by CI. CI only
  builds and tests; it does not publish anything.

## Releases

Releases are defined in
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

- **Releases are created only when a tag matching `v*` is pushed** (for example
  `v0.1.0`). Pushes to branches and pull requests never publish a release.
- Recommended versioning: `vMAJOR.MINOR.PATCH` (optionally with a suffix such as
  `v0.2.0-rc.1`). The tag should match the workspace version in `Cargo.toml`.
- Workflow permissions are limited to `contents: write` so the job can attach
  files to the GitHub release.

### To cut a release

```sh
# 1. Make sure CI is green on the commit you intend to release.
# 2. Confirm the workspace version in Cargo.toml is correct.
git tag -a v0.1.0 -m "IC-SYNC v0.1.0"
git push origin v0.1.0
```

The workflow then:

1. Builds release binaries for **Linux x86_64**, **Linux aarch64** and
   **Windows x86_64**.
2. Packages each platform into a named archive containing the binary, README,
   docs and assets.
3. Uploads each archive as a GitHub Actions artifact
   (`actions/upload-artifact`).
4. Downloads all artifacts, computes a `SHA256SUMS` file, and attaches every
   archive plus `SHA256SUMS` to the GitHub release
   (`softprops/action-gh-release`). Release notes are generated from merged
   commits.

Do not edit release assets by hand after publishing. If a mistake is found,
fix the source, bump the version and tag a new release.

### Build matrix

| Target | Runner | Toolchain | Archive |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | stable (native) | `.tar.gz` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | stable (native ARM64) | `.tar.gz` |
| `x86_64-pc-windows-msvc` | `windows-latest` | stable (native MSVC) | `.zip` |

The aarch64 job uses GitHub's native ARM64 runner, so no cross-compilation
linker setup is required. Both Linux jobs install the same Iced/tray system
dependencies described in the CI policy; the Windows job builds natively with
MSVC and needs no extra system packages.

## Artifact contents

Each platform archive contains:

```text
ic-sync[.exe]              # the release binary
README.md                  # product overview, build and security notes
docs/USER_GUIDE.md         # installation and usage
docs/RELEASE.md            # this file
docs/ARCHITECTURE.md       # internal contract
assets/                    # icon sources and generated icons
```

Archives contain **no credentials, no session/cookie JSON, no config files,
no test-account data and no local state**. The top-level `SHA256SUMS` file
lists every archive so users can verify a download:

```sh
# Linux
sha256sum --check SHA256SUMS

# Windows (PowerShell)
Get-FileHash .\ic-sync-windows-x86_64.zip -Algorithm SHA256
```
