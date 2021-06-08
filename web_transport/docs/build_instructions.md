# Building OWT QUIC SDK

## System requirements

- At least 50GB of free disk space.
- High speed network connection.
- Windows 10 for Windows build, or Ubuntu 18.04 for Ubuntu build.

## Install dependencies

Please follow [Chromium Windows build instruction](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/windows_build_instructions.md) or [Chromium Linux build instruction](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/build_instructions.md) to setup system and install `depot_tools`.

## Get the code

Create a new directory for the check out, and create a `.gclient` file in this directory. Add following code to `.gclient` file.

```
solutions = [
  { "name"        : "src/owt",
    "url"         : "https://github.com/open-webrtc-toolkit/owt-deps-quic.git",
    "deps_file"   : "DEPS",
    "managed"     : False,
    "custom_deps" : {
    },
    "custom_vars": {},
  },
]
```

Run `gclient sync` to check out SDK code, Chromium code, and other dependencies. It may take one or two hours if your network connection is not fast enough.

You will see a `src` directory after sync completes. Switch to the `src` directory for following steps.

## Additional changes

Some manually changes to Chromium code are needed before building SDK.

1. Add `"//owt/quic_transport:owt_quic_transport",` to `BUILD.gn`, after line 91. You need to revert this change before rolling Chromium revision, and redo this change after rolling.

1. Create a file `gclient_args.gni` in `build/config` with following code.

```
# Generated from 'DEPS'
build_with_chromium = true
checkout_android = false
checkout_android_native_support = false
checkout_ios_webkit = false
checkout_nacl = true
checkout_oculus_sdk = false
checkout_openxr = false
checkout_aemu = false
checkout_google_benchmark = false
```

Since we checked out code to `src/owt`, gclient cannot find buildtools under this directory. We need to add an environment variable `CHROMIUM_BUILDTOOLS_PATH`. Its value should be `<dir of .gclient file>/src/buildtools`.

## Build SDK

Run `gn gen out/debug` to generate ninja files, or `gn args out/debug` to configure GN arguments. For debug version, it may look like this
```
is_debug=true
is_component_build=false
symbol_level=1
```

You may want to set `is_component_build` to `false` in order to get a single shared library, but you can also set it to `true` to reduce the compiling time for debugging. `symbol_level` is set to `1` since `2` is conflicted with `is_component_build=false`.

Then run `ninja -C out/debug/ owt_quic_transport` to build the SDK or `ninja -C out/debug/ owt_quic_transport_tests` for end to end tests.

## Certificates

Encryption is mandatory for QUIC connections. You may generate a testing certificate by running `net/tools/quic/certs/generate-certs.sh`. It valids for 72 hours.