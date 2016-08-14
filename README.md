# seccomp_rust

NOTE: This is NOT a safe sandboxing solution, it is just a way for me to play with
thread-level sandboxing.

In its current state it is trivial to bypass even the strictest seccomp filters,
because no method is used to isolate trusted threads from untrusted threads.
