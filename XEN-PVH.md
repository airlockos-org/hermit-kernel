# Native Xen PVH branch

Upstream: https://github.com/hermit-os/kernel
Base: `ac927733a70871c4b9e33d1ad4f72823836793e6` (PVH PR #2366).

The first two integration commits preserve the previously validated boot and IPC
changes from hermit-xen `8b2abd8f6989d11071f407eb1d760b7061329c8d`.
They add Xen console/shutdown/bootstrap handling, then integrate event callbacks,
PV clocks/timers and grant-backed connections with Hermit's scheduler and futexes.
The application-facing ABI remains `sys_xen_*`. One vCPU, one authorized peer and
one connection per domain are currently supported; reconnection needs a fresh domain.

The optional Xen Cargo dependencies use the sibling `../rust-vmm-xen` checkout.
The integration repository pins that checkout; there is no second fetched Xen source.
Build with `xen,fsgsbase,kernel-stack` and nightly-2026-08-01 through its Nix builder.
Upstream PVH code and history are retained. Generic hypercalls, event/grant handling
and PV clock algorithms remain in rust-vmm/xen; Hermit owns runtime integration.

This experimental branch is validated by [hermit-xen](https://github.com/airlockos-org/hermit-xen),
which pins compatible commits of both forks, the Rust toolchain and the test laboratory.
It is not upstream-accepted or production-ready. No AirlockOS policy is included.
Use that repository's recursive checkout and Nix builder for reproducible builds and
real-Xen regression tests. Commit changes here, publish the branch, then update the
integration repository's submodule pointer. Do not rewrite upstream history.
