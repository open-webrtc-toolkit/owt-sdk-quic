
#include "owt/quic_transport/sdk/impl/quic_transport_owt_stream_impl.h"

#include <list>
#include <utility>

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_map_util.h"

namespace quic {

QuicTransportOWTStreamImpl::QuicTransportOWTStreamImpl(
    QuicStreamId id,
    QuicSession* session,
    StreamType type,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicStream(id, session, /*is_static=*/false, type),
      task_runner_(io_runner),
      //event_runner_(event_runner),
      visitor_(nullptr) {

}

QuicTransportOWTStreamImpl::QuicTransportOWTStreamImpl(
    PendingStream* pending,
    QuicSession* session,
    StreamType type,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicStream(pending, session, type, /* is_static= */ false),
      task_runner_(io_runner),
      //event_runner_(event_runner),
      visitor_(nullptr) {}

QuicTransportOWTStreamImpl::~QuicTransportOWTStreamImpl() {}

uint32_t QuicTransportOWTStreamImpl::Id() const {
  return id();
}

void QuicTransportOWTStreamImpl::SetVisitor(owt::quic::QuicTransportStreamInterface::Visitor* visitor) {
  printf("QuicTransportOWTStreamImpl::SetVisitor\n");
  visitor_ = visitor; 
}

void QuicTransportOWTStreamImpl::SendData(char* data, size_t len) {
  std::string s_data(data, len);
  task_runner_->PostTask(FROM_HERE,
          base::BindOnce(&QuicTransportOWTStreamImpl::SendDataOnCurrentThread,
              base::Unretained(this), s_data));
}

void QuicTransportOWTStreamImpl::SendDataOnCurrentThread(const std::string& data) {
  WriteOrBufferData(data, false, nullptr);
}

void QuicTransportOWTStreamImpl::processData() {
  printf("QuicTransportOWTStreamImpl::OnDataAvailable\n");
  while (sequencer()->HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      printf("No more data to read\n");
      break;
    }
    printf("Stream: %d processd:%zu, bytes in thread:%d\n",id(), iov.iov_len, base::PlatformThread::CurrentId());
    if (visitor()) {
      printf("Call visitor onData\n");
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

void QuicTransportOWTStreamImpl::OnDataAvailable() {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOWTStreamImpl::processData, base::Unretained(this)));
}

}  // namespace quic
