In this repo, we're copying the tests from original c-ares to cares-rs, then tweaking our sources to make them pass.
* When committing, don't forget to include Co-Authored-By with actual model name. Eg: Co-authored-by: DeepSeek V4.1 Flash 1017 <noreply@deepseek.com>
* Do not let Miri reach unsupported operations. Tests that use sockets, pipes, `poll`/`ppoll`/`epoll`, threads, or other real syscalls must be marked `#[cfg_attr(miri, ignore = "reason")]`. `cargo miri test` must pass without an `unsupported operation` error or abort.
