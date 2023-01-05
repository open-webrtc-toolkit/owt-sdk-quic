
#include "owt/quic_transport/sdk/impl/quic_transport_owt_stream_impl.h"

#include <list>
#include <utility>

#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_logging.h"

namespace quic {

QuicTransportOwtStreamImpl::QuicTransportOwtStreamImpl(
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

QuicTransportOwtStreamImpl::QuicTransportOwtStreamImpl(
    PendingStream* pending,
    QuicSession* session,
    StreamType type,
    base::SingleThreadTaskRunner* io_runner,
    base::SingleThreadTaskRunner* event_runner)
    : QuicStream(pending, session, /* is_static= */ false),
      task_runner_(io_runner),
      //event_runner_(event_runner),
      visitor_(nullptr) {}

QuicTransportOwtStreamImpl::~QuicTransportOwtStreamImpl() {}

uint32_t QuicTransportOwtStreamImpl::Id() const {
  return id();
}

void QuicTransportOwtStreamImpl::SetVisitor(owt::quic::QuicTransportStreamInterface::Visitor* visitor) {
  visitor_ = visitor; 
}

void QuicTransportOwtStreamImpl::CloseOnCurrentThread() {
  // TODO: Post to IO runner.
  Reset(QUIC_STREAM_CANCELLED);
}

void QuicTransportOwtStreamImpl::Close() {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtStreamImpl::CloseOnCurrentThread, base::Unretained(this)));
}

void QuicTransportOwtStreamImpl::SendData(char* data, size_t len) {
  std::string s_data(data, len);
  task_runner_->PostTask(FROM_HERE,
          base::BindOnce(&QuicTransportOwtStreamImpl::SendDataOnCurrentThread,
              base::Unretained(this), s_data));
}

void QuicTransportOwtStreamImpl::SendDataOnCurrentThread(const std::string& data) {
  if (!write_side_closed()) {
    WriteOrBufferData(data, false, nullptr);
  }
}

void QuicTransportOwtStreamImpl::processData() {
  while (sequencer()->HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    if (visitor()) {
      visitor()->OnData(this, static_cast<char*>(iov.iov_base), iov.iov_len);
    }
    sequencer()->MarkConsumed(iov.iov_len);
  }

  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }
}

void QuicTransportOwtStreamImpl::OnDataAvailable() {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicTransportOwtStreamImpl::processData, base::Unretained(this)));
}

}  // namespace quic
