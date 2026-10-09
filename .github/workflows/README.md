## CI on this fork

Two workflows run here. Both use only `actions/checkout`, pinned by commit, with a read-only token.

`carry-ci.yml` runs on pushes to `ci` and to any `1.1.1*-carry` branch, on pull requests to those branches,
and by hand (`workflow_dispatch`):

- `native`: ubuntu-24.04 and ubuntu-22.04, each with the default `./config --strict-warnings` and with the
  router's Configure options (`DEVICE_OPTIONS`, which include `no-dtls no-sm2`). Each job builds, checks
  the version text (`OpenSSL 1.1.1zX-jzN`), runs the full `make test`, then runs the carried-fix
  regression test verbosely.
- `asan`: a `--debug enable-asan enable-ubsan` build (no recovery from UB) and the full `make test`.
- `arm-qemu`: a cross build for 32-bit soft-float ARM (`arm-linux-gnueabi`, `-mcpu=cortex-a9`) with the
  router's options. A subset of `make test` runs under qemu-user with `QEMU_CPU=cortex-a9`.

`upstream-watch.yml` runs weekly (Monday 03:17 UTC) and by hand. It checks out the `tools` branch and runs
`tools/watch.py`: Amazon Linux 2's `openssl11` source RPMs, OpenSSL's security advisories and 1.1.1
vulnerability list, the cPanel/CloudLinux `ea-openssl11` backports, kzalewski/openssl-1.1.1 and this
fork's own refs. A change turns the run red until the maintainer reviews it and commits the new
`watch-state.json` to `tools`. GitHub disables a scheduled workflow after 60 days without repository
activity; the maintainer re-enables it, and runs the same script by hand meanwhile.

OpenSSL's six 1.1.1 workflows (`ci.yml`, `cross-compiles.yml`, `macos.yml`, `run-checker-ci.yml`,
`run-checker-merge.yml` and `windows.yml`) were removed here, and are disabled in the repository settings.
Every job in them asks for OpenSSL's self-hosted runners (`ubuntu-22.04-self-hosted`,
`windows-server-2022-self-hosted`, `w-mac-mini-*`), which a fork doesn't have. Several also use actions
that exist only in OpenSSL's own setup (`actions/ilammy-msvc-dev-cmd`, `actions/ilammy-setup-nasm`,
`actions/perl-actions-install-with-cpanm`, `actions/actions-rs-toolchain`). The originals stay on
`OpenSSL_1_1_1-continued`, which is never changed.

Everything in `.github/` is export-ignored, so this directory never changes a `git archive` tarball or a
build.
