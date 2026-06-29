
# GOSE - JOSE and friends for the Go developer

[![Build](https://github.com/ThalesGroup/gose/actions/workflows/ci.yml/badge.svg)](https://github.com/ThalesGroup/gose/actions/workflows/ci.yml)
[![Lint](https://github.com/ThalesGroup/gose/actions/workflows/lint.yml/badge.svg)](https://github.com/ThalesGroup/gose/actions/workflows/lint.yml)
[![Secret Scan](https://github.com/ThalesGroup/gose/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/ThalesGroup/gose/actions/workflows/secret-scan.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ThalesGroup/gose/badge)](https://scorecard.dev/viewer/?uri=github.com/ThalesGroup/gose)
[![Go Report Card](https://goreportcard.com/badge/github.com/ThalesGroup/gose)](https://goreportcard.com/report/github.com/ThalesGroup/gose)
[![GitHub release](https://img.shields.io/github/v/release/ThalesGroup/gose)](https://github.com/ThalesGroup/gose/releases/latest)

## Overview

GOSE is JOSE/JWT/JWK/JWS/JWKS implemented in Go with Helpers, and examples.

It contains implementations of the JOSE suite of types and helpers for many different use cases.

## Known Issues

* Direct encryption with AEAD mechanisms is not completely following [RFC 7516](https://tools.ietf.org/html/rfc7516)

## Mission

- Simple
- Compliant
- Safe
- Efficient
- Extensible

## Examples

Examples are provided under the `/examples` folder to illustrate correct use of this package.

## Third-party notices

[`NOTICES.md`](./NOTICES.md) lists all third-party dependency licenses and is auto-generated via `make notices` (requires [`go-licenses`](https://github.com/google/go-licenses)).

## Vulnerability check

```sh
$ govulncheck ./...

Scanning your code and 139 packages across 9 dependent modules for known vulnerabilities...

No vulnerabilities found.
```
