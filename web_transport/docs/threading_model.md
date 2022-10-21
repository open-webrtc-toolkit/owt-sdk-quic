# Threading Model

OWT QUIC SDK provides thread safe APIs, but object's creation and deletion must be called on the same thread. Objects are usually created by `WebTransportFactory`.

All calls to QUIC SDK are proxied to an internal IO thread as described below. All callbacks from QUIC SDK are called from this internal IO thread as well. It is recommended to do lightweight tasks only in callbacks.

## Deadlock

Because your thread is blocked when it calls QUIC SDK, please be cautious for deadlocks. An example to cause deadlock is:

1. An external thread calls an API of QUIC SDK.
1. QUIC SDK fires an event while the origin call is not finished.
1. Event handler calls the same external thread.

Deadlock happens because the external thread is waiting for the internal IO thread, and internal IO thread is waiting for the external thread.

## Internals

There is a thread maintained internally:

- `io_thread`: Calls to Chromium's QUIC implementation are delegated to this thread.

This thread are owned by `WebTransportFactory`. Basically, all objects created by `WebTransportFactory` re-use the same task queue based on the thread above.

Another thread `event_thread` was used for callbacks. But it will be removed.

## Reference

More information about Chromium's threading and tasks, please see [Threading and Tasks in Chrome](https://chromium.googlesource.com/chromium/src.git/+/master/docs/threading_and_tasks.md).