# Contributing to touchHLE

Please also read the [code of conduct](CODE_OF_CONDUCT.md).

## Issues

Please bear in mind that there are infinitely many apps that do not work in touchHLE right now, so please don't open issues about broken apps unless one of these applies:

- You know that this specific version of the app worked in a previous version of touchHLE and you can reproduce this.
- The app is partially working (e.g. loaded up to the menu but the main game doesn't work). The fact that an app's splash screen (Default.png) shows up doesn't mean it's partially working.

## Source control and review

Cupertab is a port based on [touchHLE](https://github.com/touchHLE/touchHLE). It started as a fork of it. Its rules differ from upstream's, and changes made here are not sent upstream.

```
$ git clone https://github.com/zeyadhost/cupertab.git
$ cd cupertab
```

Make a branch from `trunk` and open a pull request against `trunk` in this repository. Keep each pull request to one reviewable change. CI must pass before it is merged.

## Code contributions

The developer documentation can be found in [the `dev-docs` directory](dev-docs/) and throughout the codebase. At a minimum, you'll probably want to read [the building guide](dev-docs/building.md) and [the coding style guide](dev-docs/code-style.md).

Please run [`dev-scripts/format.sh`](dev-scripts/format.sh) and [`dev-scripts/lint.sh`](dev-scripts/lint.sh) on your changes before committing.

You should also run `cargo test`. [Building the integration tests requires downloading LLVM and a custom toolchain](tests/README.md), so it's understandable if you want to skip them (`cargo test -- --skip test_app`) and let the GitHub Actions CI catch any issues when you submit your pull request. Alternatively, you can download a pre-built version of the integration tests app (TestApp) from GitHub Actions CI and run it in touchHLE.

Avoid big commits that mix unrelated changes.

### Copyright, firmware and reverse engineering

(Please also read the copyright rules in the code of conduct.)

Upstream touchHLE forbids disassembling iOS components and using AI assistants. Cupertab does not. Its firmware boot mode runs Apple's own dyld, frameworks and SpringBoard from an IPSW the user supplies, and emulates the XNU kernel interface underneath them. Building that interface means studying how those binaries call the kernel: syscalls, Mach traps and messages, and IOKit methods.

The rules that still apply:

* Never commit, host or link to Apple firmware, decryption keys or other Apple binaries. Users provide their own IPSW, and it stays on their machine.
* Never copy Apple code into this repository. Studying a binary to learn the interface it expects is fine; reproducing its implementation is not.
* Do not use leaked code, documentation or tools.
* Never break Apple's app DRM. Encrypted apps are not supported.
* Open-source code is still under copyright. Only bring it in under a compatible license, as a dependency or with its license kept.
* AI assistance is allowed. You are responsible for every change you submit and must be able to explain it.
* Vendored projects such as `vendor/gl4es` keep their own rules for changes sent to them.
