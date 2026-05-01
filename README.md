# Graph-based framework for distributed cryptographic protocols

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coverage][coverage-image]][coverage-link]


*Rounds? Where we're going, we don't need rounds!*

Most cryptographic papers describe multi-party protocols in terms of rounds.
The main idea of this crate is to treat rounds as a low-level implementation detail the user need not worry about, and instead focus on dependencies between data ("when I receive `x`, calculate and send out `y`").
The crate will bundle the messages internally.

This approach opens up many features that are hard to implement using the round-based formalism.
See [the book](https://publicfields.net/ayatori) for more details.
The goal of the project is to bring the implementation of the protocol close to its description in the paper to simplify audit, and to make sure everything that can be handled automatically (signing messages, preventing denial of service and replay attacks, generating evidence of malicious behavior etc) is done so.

A working example of a protocol is too lengthy to be included here, but one is reviewed in [the book](https://publicfields.net/ayatori), and a number of examples can be found in the [`integration-tests`](https://github.com/fjarri/ayatori/tree/master/integration-tests) crate in the repository.


[crate-image]: https://img.shields.io/crates/v/ayatori.svg
[crate-link]: https://crates.io/crates/ayatori
[docs-image]: https://docs.rs/ayatori/badge.svg
[docs-link]: https://docs.rs/ayatori/
[license-image]: https://img.shields.io/crates/l/ayatori
[build-image]: https://github.com/fjarri/ayatori/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/fjarri/ayatori/actions/workflows/ci.yml
[coverage-image]: https://codecov.io/gh/fjarri/ayatori/branch/master/graph/badge.svg
[coverage-link]: https://codecov.io/gh/fjarri/ayatori
