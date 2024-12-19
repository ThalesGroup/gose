# Cryptography Bill Of Material

This folder contains a sample of Cryptography Bill Of Material (CBOM) file. For now, the CBOM is
available only in the CycloneDX format.

In the future, the CBOM might be released as a metadata in the Github release tab, and might be
merged with an SBOM and/or with an attestation of provenance.

- [1. How was the CBOM Generated ?](#1-how-was-the-cbom-generated-)
- [2. Crafting the JOSE / JWA CBOM Reference Database](#2-crafting-the-jose--jwa-cbom-reference-database)
  - [2.1. Acronyms](#21-acronyms)
  - [2.2. Several Heterogeneous Sources of External References for JOSE](#22-several-heterogeneous-sources-of-external-references-for-jose)
  - [2.3. Cross-Reference Information from IANA, RFC7518 and NIST](#23-cross-reference-information-from-iana-rfc7518-and-nist)


## 1. How was the CBOM Generated ?

A list of "Supported Algorithms" is available in the source code at [./jose/types.go](./jose/types.go).
Then a soon to be released tool called [`xbom-manager`](https://wwww.github.com/ThalesGroup/xbom-manager)
is used with a JOSE algorithms knowledge base to create a CycloneDX formated Crypto BOM file.

```bash
xbom-manager generate cbom cyclonedx --csvfile algo-list.csv --pretty --spec-version 1.6 > cbom.cyclonedx.json
```

To know more about the JOSE algorithms knowledge base, refer to the section
[Crafting the JOSE / JWA CBOM Reference Database](#2-crafting-the-jose--jwa-cbom-reference-database).

> The tool will soon be available here at [`xbom-manager`](https://wwww.github.com/ThalesGroup/xbom-manager). It is still under prototyping right now.

## 2. Crafting the JOSE / JWA CBOM Reference Database

> Note: this will be thurther explained here: [`xbom-manager`](https://wwww.github.com/ThalesGroup/xbom-manager).

### 2.1. Acronyms

- JCA: Java Cryptography Architecture
- JOSE: JSON Object Signing and Encryption
- JWA: JSON Web Algorithms
- OID: Object Identifier

### 2.2. Several Heterogeneous Sources of External References for JOSE

| Organism | Reference Name                               | Link                                                                                                                                                          |
|----------|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IANA     | JSON Web Signature and Encryption Algorithms | <https://www.iana.org/assignments/jose/jose.xhtml>                                                                                                              |
| IETF     | RFC 7518 JSON Web Algorithms (JWA)           | <https://www.rfc-editor.org/rfc/rfc7518>                                                                                                                        |
| NIST     | NIST Post-Quantum Cryptography               | [Link](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)) |

As we were looking for metadata that describes JOSE and JWA, we found a nice
[CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv)
from the [IANA website](https://www.iana.org/assignments/jose/jose.xhtml)
containing the following information:

| Column Name `web-signature-encryption-algorithms.csv` | Source / Reference                                                                                    |
|-------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `Algorithm Name`                                      | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `Algorithm Description`                               | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `Algorithm Usage Location(s)`                         | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `JOSE Implementation Requirements`                    | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `Change Controller`                                   | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `Reference`                                           | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |
| `Algorithm Analysis Document(s)`                      | [IANA's JOSE CSV file](https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv) |

This information is a good start to build a CBOM. But it is lacking
information on some parameters such as the `OID` (Object Identifier) and the
`nistQuantumSecurityLevel` which are both defined in
[CycloneDX 1.6](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json):.

`OID` information can be found in the
[RFC 7518 JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518).

`nistQuantumSecurityLevel` needs to be manually set for each cryptographic
primitive by following the [NIST PQC guidelines](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria))).

### 2.3. Cross-Reference Information from IANA, RFC7518 and NIST

To get the best data from JOSE / JWA information from IANA, RFC7518 and NIST, we
decided to cross-reference, or _join_, the different databases to create a
reference database.

Full JOSE list in a `.csv` format will soon be available at [`xbom-manager`](https://wwww.github.com/ThalesGroup/xbom-manager).

File [`./assets/cbom/algo-list.csv`](./assets/cbom/algo-list.csv) is in fact an extract of the full
JOSE algorithms knowledge base. But it only contains the algorithms from file
[./jose/types.go](./jose/types.go).