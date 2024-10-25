# DISCONTINUATION OF PROJECT #
This project will no longer be maintained by Intel.  
Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  
Intel no longer accepts patches to this project.  
If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  

# Open WebRTC Toolkit QUIC SDK

Open WebRTC Toolkit QUIC SDK based on the Chromium project to provide C++ APIs for both server side and client side QUIC support.

## Code structure

This repository has two projects for QUIC support. They might be merged in the future.

- **quic_io** is developed for QUIC based internal I/O among OWT server agents. 
- **quic_transport** is a SDK for both server side and client side [WebTransport](https://w3c.github.io/webtransport/) support.

## How to build

Please refer to [this file](quic_io/readme.md) for build instructions for quic_io and [this file](quic_transport/docs/build_instructions.md) for build instructions for quic_transport.

## How to contribute
We warmly welcome community contributions to Open WebRTC Toolkit Media Server repository. If you are willing to contribute your features and ideas to OWT, follow the process below:
- Make sure your patch will not break anything, including all the build and tests
- Submit a pull request onto https://github.com/open-webrtc-toolkit/owt-deps-quic/pulls
- Watch your patch for review comments, if any, until it is accepted and merged. The OWT project is licensed under Apache License, Version 2.0. By contributing to the project, you agree to the license and copyright terms therein and release your contributions under these terms.

## How to report issues
Use the "Issues" tab on Github.

## See Also
https://webrtc.intel.com
