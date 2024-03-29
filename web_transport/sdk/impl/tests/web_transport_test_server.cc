/*
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Similar to net/tools/quic/quic_simple_server_bin.cc, it starts a WebTransport
// echo server for testing.

#include "base/test/bind.h"
#include "base/threading/thread.h"
#include "impl/tests/web_transport_echo_visitors.h"
#include "impl/web_transport_owt_server_impl.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"

int main(int argc, char* argv[]) {
  QuicSystemEventLoop event_loop("web_transport_test_server");
  const char* usage = "Usage: web_transport_test_server [options]";
  std::vector<std::string> non_option_args =
      ::quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    ::quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  base::Thread::Options io_thread_options;
  io_thread_options.message_pump_type = base::MessagePumpType::IO;
  base::Thread io_thread("web_transport_test_server_io_thread");
  io_thread.StartWithOptions(std::move(io_thread_options));
  base::Thread::Options event_thread_options;
  event_thread_options.message_pump_type = base::MessagePumpType::IO;
  base::Thread event_thread("web_transport_test_server_event_thread");
  event_thread.StartWithOptions(std::move(event_thread_options));
  auto proof_source = ::quic::CreateDefaultProofSource();
  auto server_visitor = std::make_unique<owt::quic::test::ServerEchoVisitor>();
  base::WaitableEvent event;
  std::unique_ptr<owt::quic::WebTransportOwtServerImpl> server;
  io_thread.task_runner()->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        server = std::make_unique<owt::quic::WebTransportOwtServerImpl>(
            20001, std::vector<url::Origin>(), std::move(proof_source),
            &io_thread, &event_thread);
        event.Signal();
      }));
  event.Wait();
  server->SetVisitor(server_visitor.get());
  server->Start();

  base::RunLoop run_loop;
  run_loop.Run();
  return 0;
}
