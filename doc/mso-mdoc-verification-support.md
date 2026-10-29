# Support for ISO/IEC 18013-5 mso_mdoc (mDL)

This document describes how **vc-verifier** validates and verifies `mso_mdoc` credentials
(Mobile Security Object / mobile Driving Licence) encoded as **base64url CBOR** with a
**COSE_Sign1** `issuerAuth`.

Related: [GitHub issue #300](https://github.com/inji/vc-verifier/issues/300),
[inji-certify#1123](https://github.com/inji/inji-certify/issues/1123) (ISO-conformant issuer fixtures).

---

## Input encoding

- Credential string must be **base64url** (no padding required) over CBOR.
- **Base45** (QR transport) is **not** accepted; callers must decode Base45 (/zlib) first if needed.

## Input shapes (`MsoMdocVerifiableCredential.parse`)

| Shape | Structure | `isLatest` |
|---|---|---|
| **A** (OpenID4VCI 1.0) | `{ issuerAuth, nameSpaces }` | `true` |
| **B** (legacy) | `{ docType, issuerSigned: { issuerAuth, nameSpaces } }` | `false` |
| **C** (legacy) | `{ documents: [ { docType, issuerSigned } ] }` (only `documents[0]`) | `false` |

Detection order: C → B → A.

---

## Validation (`MsoMdocValidator`)

- Mandatory MSO fields: `version`, `digestAlgorithm`, `valueDigests`, `deviceKeyInfo`, `docType`, `validityInfo`
- `version` must be `"1.0"`
- `digestAlgorithm` must be `SHA-256`, `SHA-384`, or `SHA-512`
- `validityInfo` dates (`validFrom`, `validUntil`, and `signed` when latest): no fractional seconds, must end in `Z`
- `validFrom` must not be in the future (3s skew via `DateUtils`)
- `validUntil` must be after `validFrom`
- Past `validUntil` → soft failure `ERR_VC_EXPIRED` (same pattern as other formats)
- For **shape A only**: `signed` required; `validFrom` must not be before `signed`; MSO payload must be tag-24

## Verification (`MsoMdocVerifier`)

Order of checks:

1. COSE protected header must contain `alg`
2. DS certificate from `x5chain`: within `notBefore` / `notAfter`
3. For `docType` `org.iso.18013.5.1.mDL`:
   - KeyUsage includes `digitalSignature` and is critical
   - ExtendedKeyUsage includes `1.0.18013.5.1.2` and is critical
4. MSO `signed` falls within DS certificate validity
5. COSE signature verifies with DS public key
6. Value digests: each received `nameSpaces` record is tag-24; hash **IssuerSignedItemBytes**; match MSO digests; reject duplicate `digestID`s; MSO digests without a received record are allowed (selective disclosure)
7. Credential `docType` matches MSO `docType` (legacy shapes)
8. For mDL: `issuing_country` matches DS `countryName` (mandatory when verifying mDL); `issuing_jurisdiction` matches DS `stateOrProvinceName` when both present; `issue_date` (if disclosed) is a full date and not after `validFrom`

## Out of scope

- IACA trust chain / CRL
- IACA ↔ DS `countryName` match
- Algorithms other than ES256
- DeviceResponse / holder `deviceKey` presentation binding

## Pending confirmation (issue #300 §2 #4 and #5)

- Require MSO tag-24 for **all** shapes (currently shape A only)
- Require `validFrom` ≥ `signed` for **all** shapes (currently shape A only)

## Error codes

See `CredentialValidatorConstants` and the **mso_mdoc Format VC Error Codes** table in
[`vc-verifier/kotlin/README.md`](../vc-verifier/kotlin/README.md).

## Test fixtures

ISO-conformant pass-path fixtures (DS EKU `1.0.18013.5.1.2`, mandatory mDL claims including
`issuing_country`) are tracked on the Certify side. Until they land, success-path verifier tests
remain `@Disabled`. Fail-path and structural validator tests run without those fixtures.
