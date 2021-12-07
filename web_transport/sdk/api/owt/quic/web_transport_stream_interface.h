/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OWT_WEB_TRANSPORT_WEB_TRANSPORT_STREAM_INTERFACE_H_
#define OWT_WEB_TRANSPORT_WEB_TRANSPORT_STREAM_INTERFACE_H_

#include "owt/quic/export.h"
#include "stddef.h"
#include "stdint.h"

namespace owt {
namespace quic {
class OWT_EXPORT WebTransportStreamInterface {
 public:
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when new data is available.
    virtual void OnCanRead() = 0;
    // Called when stream is ready to write new data. It doesn't called before
    // first write. Before first write, please check IsSessionReady().
    // TODO: Add OnSessionReady to WebTransportSessionInterface::Visitor.
    virtual void OnCanWrite() = 0;
    // Called when final incoming data is read.
    virtual void OnFinRead() = 0;
  };
  virtual ~WebTransportStreamInterface() = default;
  // QUIC stream ID.
  virtual uint32_t Id() const = 0;
  virtual void SetVisitor(Visitor* visitor) = 0;
  // Write or buffer data. Returns the length of data written or buffered.
  // Current implementation always returns 0 or `length`.
  virtual size_t Write(const uint8_t* data, size_t length) = 0;
  // Reads at most `length` bytes into `data` and returns the number of bytes
  // actually read.
  virtual size_t Read(uint8_t* data, size_t length) = 0;
  // Indicates the number of bytes that can be read from the stream.
  virtual size_t ReadableBytes() const = 0;
  // Close the stream, send FIN to remote side.
  virtual void Close() = 0;
  // Bytes of data buffered.
  virtual uint64_t BufferedDataBytes() const = 0;
  // Ready to write new data.
  virtual bool CanWrite() const = 0;
};
}  // namespace quic
}  // namespace owt

#endif