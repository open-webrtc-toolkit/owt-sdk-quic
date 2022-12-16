// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUIC_TRANSPORT_OWT_STREAM_IMPL_H_
#define QUIC_TRANSPORT_OWT_STREAM_IMPL_H_

#include "absl/base/macros.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_session.h"
#include "owt/quic/quic_transport_stream_interface.h"
#include "base/task/single_thread_task_runner.h"

namespace quic {

class QUIC_EXPORT_PRIVATE QuicTransportOWTStreamImpl : public QuicStream,
                                                       public owt::quic::QuicTransportStreamInterface {
 public:

  QuicTransportOWTStreamImpl(QuicStreamId id,
                QuicSession* session,
                StreamType type,
                base::SingleThreadTaskRunner* io_runner,
                base::SingleThreadTaskRunner* event_runner);
  QuicTransportOWTStreamImpl(PendingStream* pending,
                       QuicSession* session,
                       StreamType type,
                       base::SingleThreadTaskRunner* io_runner,
                       base::SingleThreadTaskRunner* event_runner);
  QuicTransportOWTStreamImpl(const QuicTransportOWTStreamImpl&) = delete;
  QuicTransportOWTStreamImpl& operator=(const QuicTransportOWTStreamImpl&) = delete;
  ~QuicTransportOWTStreamImpl() override;

  // QuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  uint32_t Id() const override;

  void SetVisitor(owt::quic::QuicTransportStreamInterface::Visitor* visitor) override;
  void SendData(char* data, size_t len) override;

  // Returns true if the sequencer has delivered the FIN, and no more body bytes
  // will be available.
  bool IsClosed() { return sequencer()->IsClosed(); }
  void Close() override;

 protected:
  owt::quic::QuicTransportStreamInterface::Visitor* visitor() { return visitor_; }

 private:
  void SendDataOnCurrentThread(const std::string& data);
  void CloseOnCurrentThread();
  void processData();
  base::SingleThreadTaskRunner* task_runner_;
  //base::SingleThreadTaskRunner* event_runner_;
  owt::quic::QuicTransportStreamInterface::Visitor* visitor_;
};

}  // namespace quic

#endif  // QUIC_TRANSPORT_OWT_STREAM_IMPL_H_
