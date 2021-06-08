#
# Copyright (C) 2021 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

# This Dockerfile creates a docker image for building QUIC SDK.

FROM ubuntu:20.04
SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git curl wget python lsb-release tzdata
RUN mkdir workspace
WORKDIR /workspace
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH="$PATH:/workspace/depot_tools"
RUN mkdir quic
WORKDIR /workspace/quic
RUN echo $'solutions = [\n\
  {\n\
    "name"        : "src/owt",\n\
    "url"         : "https://github.com/open-webrtc-toolkit/owt-deps-quic.git",\n\
    "deps_file"   : "DEPS",\n\
    "managed"     : False,\n\
    "custom_deps" : {\n\
    },\n\
    "custom_vars": {},\n\
  },\n\
]' > .gclient
RUN gclient sync
WORKDIR /workspace/quic/src
# Commands are ran in sudo mode.
RUN sed -i 's/sudo //g' build/install-build-deps.sh
# snapcraft cannot be installed.
RUN sed -i 's/{dev_list} snapcraft/{dev_list}/g' build/install-build-deps.sh
RUN ./build/install-build-deps.sh
