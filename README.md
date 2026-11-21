![build-and-test](https://github.com/vdudouyt/cares-rs/actions/workflows/cargo-test.yaml/badge.svg) ![build-and-test](https://github.com/vdudouyt/cares-rs/actions/workflows/benchmarks.yaml/badge.svg)

## Synopsis

Requires nightly Rust for the allocator API; `rust-toolchain.toml` selects it.

Build and run example.c:
```nohighlight
$ gcc example.c -lcares -o example
$ ./example google.com
Resolved: 142.250.179.206
```

## Generic async sockets

The async runtime that drives the resolver is also usable for arbitrary
protocols. It follows the c-ares model: the application owns the event loop,
asks `Runtime` for its interests and timeout, waits itself, and hands
readiness back with `Runtime::process` (the `ares_process()` step). See
[ASYNC_RUNTIME.md](ASYNC_RUNTIME.md) and the
[`tcp_hello`](examples/tcp_hello.rs) example.
