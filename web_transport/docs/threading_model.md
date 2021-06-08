# Threading Model

OWT QUIC SDK provides thread safe APIs, but object's creation and deletion must be called on the same thread. Objects are usually created by `QuicTransportFactory`.

## Internals

There are two threads maintained internally:

- `io_thread`: Calls to Chromium's QUIC implementation are delegated to this thread.
- `event_thread`: Callbacks and events are fired on this thread. We may move to sequence later.

These two threads are owned by `QuicTransportFactory`. Basically, all objects created by `QuicTransportFactory` re-use the same task queues based on the two threads above.

## Reference

More information about Chromium's threading and tasks, please see [Threading and Tasks in Chrome](https://chromium.googlesource.com/chromium/src.git/+/master/docs/threading_and_tasks.md).