A Rust rewrittement for c-ares asynchronous DNS resolver library:

Rules:
* Use non-blocking I/O with following the reactor pattern. Never use blocking I/O requests
* When porting tests, copy them from original c-ares implementation in /root/c-ares-1.34.6/. Make as less changes as possible for the sake of logical consistency and easier updates. You're allowed to comment EDNS and malloc-related tests, though.

### Testing

Mainly we're using the original c-ares tests in tests/cares-tests/ to emphasize behavior as close to original as possible. Currently it's still missing some tests, so we're moving them from original libcares repository.

IMPORTANT: When porting the tests, make sure to just copy the .c files without modifying them (perhaps with an exception to malloc/free tests).
