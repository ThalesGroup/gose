
# GOSE - JOSE and friends for the Go developer

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

## Vulnerability check

```sh
$ govulncheck ./...                                                                                                                       ─╯
Scanning your code and 139 packages across 9 dependent modules for known vulnerabilities...

No vulnerabilities found.
```
