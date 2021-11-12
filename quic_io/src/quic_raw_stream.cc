
#include "net/tools/quic/raw/quic_raw_stream.h"

#include <list>
#include <utility>

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_map_util.h"

namespace quic {

QuicRawStream::QuicRawStream(
    QuicStreamId id,
    QuicSession* session,
    StreamType type)
    : QuicStream(id, session, /*is_static=*/false, type),
      visitor_(nullptr) {

}

QuicRawStream::QuicRawStream(
    PendingStream* pending,
    QuicSession* session,
    StreamType type)
    : QuicStream(pending, session, type, /* is_static= */ false),
      visitor_(nullptr) {}

QuicRawStream::~QuicRawStream() {}

void QuicRawStream::OnDataAvailable() {
  printf("QuicRawStream::OnDataAvailable\n");
  while (sequencer()->HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      printf("No more data to read\n");
      break;
    }
    printf("Stream: %d processd:%d, bytes in thread:%d\n",id(), iov.iov_len, base::PlatformThread::CurrentId());
    if (visitor()) {
      visitor()->OnData(this, static_cast<char*>(iov.iov_base), iov.iov_len);
    }
    sequencer()->MarkConsumed(iov.iov_len);
  }

  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    printf("set sequencer unblocked\n");
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    printf("write side closed or fin buffered\n");
    return;
  }
}

}  // namespace quic
