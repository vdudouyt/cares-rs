# Async_Runtime
A lightweight async runtime inspired by **Tokio** and **Smol**, designed specifically for the **cares-rs** project.

Unlike for the latter ones, it has the following distinctive characteristics:

* **Zero global state**: incapsulated into ``struct Runner`` (normally owned by ``AresChannel``)
* **External event loop**: polls are externally fulfilled by providing ready fds on each iteration (see ``ares_process()``)

## Threading rules

* Each runner is single-threaded
* ``.spawn()`` starts an asynchronous task in the same runner, not a thread
* Multithreading is safe, simultaneously accessing the same channel isn't (and not feasible from safe code)

## Most common methods

| Method | Purpose |
|---|---|
|Runtime::default()|Create a new runtime|
|rt.spawn(fut, oncomplete)|Spawn a new task and runs oncomplete when future completes|
|rt.register_socket(dyn Socket)|Registers an existing socket, then returns Rc<AsyncSocket>|
|rt.create_udp(sock_addr)|Create a new UDP socket|
|rt.create_tcp(sock_addr)|Create a new TCP socket|
|rt.connect_tcp(sock_addr)|Create, connects and wait for completion|
|rt.timer_at(instant)|Waits until specified instant|
|rt.active_count()|Number of live tasks|
|rt.interests()|Get all pendings fds. (Typically passed to ``select()``)|
|rt.process(predicate)|Runs predicate against all pending fds and processes matched ones. (Typically the ones that got ``select()``ed)|
|rt.process_events(fdlist)|Processes all fields specified in a fdlist. (Typically used with ``epoll()``)|
|rt.advance_timers(instant)|Fires all timers due before specified moment|

## Tutorial

Suppose you're writing a cares-like asynchronous greeter protocol library targeting typical C applications like that:
<details>
<summary><b>greeter.c</b></summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <greeter.h>

// build: make   (or: cargo build --release && gcc ... -lgreeter)
// $ ./greeter_example Alice 127.0.0.1:7878
// Hello, Alice!

static void callback(void *arg, int status, const char *reply) {
    (void)arg;
    if (status != GREETER_SUCCESS) {
        fprintf(stderr, "Greeting failed: status %d\n", status);
        return;
    }
    printf("%s\n", reply);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <name> <host:port>\n", argv[0]);
        return 1;
    }

    greeter_channel channel;
    if (greeter_init(&channel) != GREETER_SUCCESS) {
        fprintf(stderr, "Failed to init greeter channel\n");
        return 1;
    }

    if (greeter_send(channel, argv[2], argv[1], callback, NULL) != GREETER_SUCCESS) {
        fprintf(stderr, "Failed to send greeting\n");
        greeter_destroy(channel);
        return 1;
    }

    for (;;) {
        fd_set readers, writers;
        FD_ZERO(&readers);
        FD_ZERO(&writers);

        int nfds = greeter_fds(channel, &readers, &writers);
        if (nfds == 0) break;  // no more pending requests

        struct timeval tv_buf;
        struct timeval *tv = greeter_timeout(channel, NULL, &tv_buf);

        int rc = select(nfds, &readers, &writers, NULL, tv);
        if (rc < 0) {
            perror("select");
            break;
        }

        greeter_process(channel, &readers, &writers);
    }

    greeter_destroy(channel);
    return 0;
}
```

</details>

In the pre-async/await era, messing with asynchronous code meant dealing with whole callback hierarchy: not something would immediately bite, yet growing fangs very quickly.

But nowadays, it's possible to write asynchronous code looking almost just as if it was synchronous code - thanks for evolution of programming languages in the last decades.

So, let's begin with implementing ``async fn greet()`` - the most essential thing in our greeter protocol library:

<details>
<summary><b>async fn greet()</b></summary>
  
```rust
async fn greet(
    runtime: Runtime<GreeterError>,
    server: SocketAddr,
    name: String,
) -> GreeterResult {
    let sock = runtime.connect_tcp(server, Instant::now() + CONNECT_TIMEOUT).await?;

    let request = format!("{name}\n");
    sock.write_all(request.as_bytes(), Instant::now() + IO_TIMEOUT).await?;

    let mut reply = read_to_end(&sock, MAX_REPLY, Instant::now() + IO_TIMEOUT).await?;
    if reply.is_empty() {
        return Err(GreeterError::Closed);
    }
    if !reply.ends_with(b"\n") {
        return Err(GreeterError::BadReply);
    }
    reply.pop();
    if reply.ends_with(b"\r") {
        reply.pop();
    }
    Ok(String::from_utf8(reply)?)
}
```
</details>

As you see, it's already depicting all the stages a single greeter protocol request/response cycle is going through: no callbacks, no explicit state, no messing with state machines - all the meaty things concentrated in the same place.

Yet, it's completely ready to be spawned as an asynchronous task in a worker with cooperative multitasking - shared with another tasks.

The bad news is, however, that we still have to deal with writing the C interface. Fortunately, this module has everything we need. Let's begin with writing ``greater_init()`` - it just writes an opaque pointer to a newly-allocated ``GreeterChannelData`` structure, the only member field of which is an instance of ``async_runtime::Runtime``:

<details>
<summary><b>unsafe extern "C" fn greeter_init()</b></summary>

```rust
#[no_mangle]
pub unsafe extern "C" fn greeter_init(out: *mut greeter_channel) -> c_int {
    if out.is_null() {
        return GREETER_EBADSTR;
    }
    let channel = Box::new(GreeterChannelData {
        rt: Runtime::default(),
    });
    unsafe { *out = Box::into_raw(channel) };
    GREETER_SUCCESS
}
```
</details>

``greeter_send()`` just spawns a new ``async fn greet()`` and returns immediately:

<details>
<summary><b>unsafe extern "C" fn greeter_init()</b></summary>

```rust
#[no_mangle]
pub unsafe extern "C" fn greeter_send(
    channel: greeter_channel,
    server: *const c_char,
    name: *const c_char,
    callback: greeter_callback,
    arg: *mut c_void,
) -> c_int {
    let channel = unsafe { &*channel };
    let Ok(server) = (unsafe { CStr::from_ptr(server) }).to_str() else {
        return GREETER_EBADSTR;
    };
    let Ok(server) = server.parse::<SocketAddr>() else {
        return GREETER_EBADSTR;
    };
    let Ok(name) = (unsafe { CStr::from_ptr(name) }).to_str() else {
        return GREETER_EBADSTR;
    };
    if name.is_empty() || name.len() > MAX_NAME || name.contains(['\n', '\r']) {
        return GREETER_EBADSTR;
    }
    let name = name.to_owned();

    let future = greet(channel.rt.handle(), server, name);
    let on_complete = move |result: Result<GreeterResult, GreeterError>| {
        let reply = result
            .and_then(|result| result)
            .map_err(|err| err.status_code())
            .and_then(|reply| CString::new(reply).map_err(|_| GREETER_EBADRESP));
        match reply {
            Ok(reply) => unsafe { callback(arg, GREETER_SUCCESS, reply.as_ptr()) },
            Err(status) => unsafe { callback(arg, status, std::ptr::null()) },
        }
    };
    if channel.rt.spawn(future, on_complete).is_err() {
        return GREETER_EDESTRUCTION;
    }
    // Start queued work so sockets register their interests and immediate
    // failures deliver their callbacks before the host waits for I/O.
    channel.rt.run_ready();
    GREETER_SUCCESS
}
```
</details>

``greeter_fds()`` populates both ``fd_set``s for a C program - so that it could call a blocking ``select()`` on them:

<details>
<summary><b>unsafe extern "C" fn greeter_fds()</b></summary>
  
```rust
pub unsafe extern "C" fn greeter_fds(
    channel: greeter_channel,
    read_fds: *mut libc::fd_set,
    write_fds: *mut libc::fd_set,
) -> c_int {
    if channel.is_null() || read_fds.is_null() || write_fds.is_null() {
        return 0;
    }
    let channel = unsafe { &*channel };
    let interests = channel.rt.interests();
    let mut nfds = 0;
    for (fd, writable) in interests {
        if fd >= libc::FD_SETSIZE as i32 {
            continue;
        }
        unsafe {
            if writable {
                libc::FD_SET(fd, write_fds);
            } else {
                libc::FD_SET(fd, read_fds);
            }
        }
        nfds = nfds.max(fd + 1);
    }
    nfds
}
```
</details>

``greeter_timeout()`` returns for how long the user can block before the next ``ares_process()`` call - important if we got any timers in our asynchronous code:

<details>
<summary><b>unsafe extern "C" fn greeter_timeout()</b></summary>

```rust
pub unsafe extern "C" fn greeter_timeout(
    channel: greeter_channel,
    maxtv: *mut libc::timeval,
    tv: *mut libc::timeval,
) -> *mut libc::timeval {
    let Some(channel) = (unsafe { channel.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let Some(tv) = (unsafe { tv.as_mut() }) else {
        return std::ptr::null_mut();
    };
    let Some(ms) = channel.next_timeout_ms() else {
        // No timers: return the caller's cap, or NULL when there is none.
        return maxtv;
    };

    if unsafe { maxtv.as_ref() }.is_some_and(|cap| timeval_to_ms(cap) < ms as i128) {
        return maxtv;
    }

    *tv = timeval_from_ms(ms);
    tv
}
```
</details>

``fn greeter_process()`` tells runtime which fds are ready to process and advances any possible timers to ``Instant::now()`` value:

<details>
<summary><b>unsafe extern "C" fn greeter_process()</b></summary>

```rust
pub unsafe extern "C" fn greeter_process(
    channel: greeter_channel,
    read_fds: *mut libc::fd_set,
    write_fds: *mut libc::fd_set,
) {
    if channel.is_null() || read_fds.is_null() || write_fds.is_null() {
        return;
    }
    let channel = unsafe { &*channel };
    let readers: &libc::fd_set = unsafe { &*read_fds };
    let writers: &libc::fd_set = unsafe { &*write_fds };

    channel.rt.process(|fd, writable| {
        let set = if writable { writers } else { readers };
        unsafe { libc::FD_ISSET(fd, set as *const libc::fd_set as *mut libc::fd_set) }
    });
    channel.rt.advance_timers((Instant::now()));
}
```
</details>

At this moment, we have everything we need. Let's compile our library, link it with ``example.c`` and run it against a greeter server that accepts a TCP connection, reads a person name followed by newline, sends a greeting message to that person and closes a connection in your local network:
```
$ cargo build --release
$ gcc example.c libgreeter.so -o example
$ ./example 127.0.0.1:7878 "John Doe"
Hello, John Doe!
```

If you have read until this point, you're already understanding the most essential parts of ``cares-rs`` architecture. Wish a happy hacking!
