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
The credential shape (A/B/C) only decides where `IssuerSigned` is found (and the outer `docType` match).
Every check below runs the same way for all shapes.

- `version` must match `1.<minor>` exactly (for example, `"1.0"` or `"1.1"`; `"1"`, `"01.0"`, `"1.0.0"` are rejected)
- `digestAlgorithm` must be `SHA-256`, `SHA-384`, or `SHA-512`
- `valueDigests` must follow the ISO layout `{ namespace (tstr) => { digestID (uint) => digest (bstr) } }`, else `ERR_INVALID_MSO`. The non-ISO `valueDigests.nameSpaces` wrapper is no longer accepted. Each MSO digestID key must be &lt; 2³¹ (`ERR_INVALID_MSO`)
- `signed`, `validFrom` and `validUntil` are mandatory for **all** shapes (`ERR_INVALID_DATE_MSO` when absent)
- `validityInfo` dates (`signed`, `validFrom`, `validUntil`, `expectedUpdate`): tag 0 (`tdate`) in every shape, `YYYY-MM-DDThh:mm:ssZ` (no fractional seconds, no offset)
- `validFrom` and `signed` must not be in the future; `validFrom` must not be before `signed` (all shapes, "validFrom must not be earlier than signed")
- `validUntil` must be after `validFrom`
- Past `validUntil` → soft failure `ERR_VC_EXPIRED` (same pattern as other formats)
- MSO payload must be tag-24 (`#6.24(bstr .cbor MobileSecurityObject)`) for **all** shapes, else `ERR_INVALID_MSO`

### Clock and tolerance

Every mdoc comparison against "now" uses one clock and one tolerance,
`MDOC_CLOCK_SKEW_TOLERANCE_MS = 3000`, applied leniently:

| Check | Fails only when |
|---|---|
| DS certificate not yet valid | `now + tol < notBefore` |
| DS certificate expired | `now - tol > notAfter` |
| `validFrom` / `signed` in the future | `now + tol < date` |
| `validUntil` expired | `now - tol > validUntil` |

`signed` vs the DS certificate window compares two issuer timestamps, so it has no tolerance.
"Now" comes from `MsoMdocVerificationOptions.currentTimeMillis` (default `System::currentTimeMillis`),
which tests use to pin the clock.

## Verification (`MsoMdocVerifier`)

Order of checks:

1. COSE protected header must contain `alg` (`ERR_MISSING_ALG`; a header that is not a bstr-encoded map → "COSE protected header is malformed") and the value must be ES256 (`-7`); anything else → `ERR_INVALID_ALG`. The DS certificate key must be EC P-256 (`ERR_INVALID_ALG`). ES384 / ES512 / EdDSA are tracked in vc-verifier#302
2. DS certificate from `x5chain`: within `notBefore` / `notAfter` (with tolerance, see above). Hard failure `ERR_INVALID_DS_CERT_VALIDITY`
3. For `docType` `org.iso.18013.5.1.mDL` **when `mdocStrictProfile=true` (default)**:
   - KeyUsage includes `digitalSignature` and is critical
   - ExtendedKeyUsage includes `1.0.18013.5.1.2` and is critical
   - ISO Table B.3 makes this mandatory; it stays behind the strict flag only until Certify DS certificates conform (inji-certify#1132)
4. MSO `signed` falls within DS certificate validity (inclusive). `signed` is required; absent or unparseable → `ERR_INVALID_VALIDITY_INFO_MSO`
5. COSE signature verifies with DS public key. This does **not** establish IACA trust (`verifyCertificateChain` is currently a no-op / out of scope)
6. Value digests: each received `nameSpaces` record is tag-24 wrapping a map with a text `elementIdentifier` and an `elementValue` (`ERR_INVALID_ISSUER_SIGNED_ITEM`); hash the **exact on-the-wire** `IssuerSignedItemBytes` (and check the raw slice decodes to the same item cbor-java parsed); `digestID` &lt; 2³¹; `random` ≥ 16 bytes; reject duplicate `digestID`s and duplicate `elementIdentifier`s within a namespace; MSO digests without a received record are allowed (selective disclosure).
   A namespace or `digestID` absent from the MSO, a digest mismatch, or a raw/parsed disagreement → `LikelyTamperedException` (`ERR_LIKELY_TAMPERED`). Structural problems stay `ValidationException`. The returned message never includes namespaces or digestIDs; those are logged only
   - Raw item bytes are captured by a minimal CBOR scanner that rejects indefinite-length encoding. This is a deliberate restriction, not an ISO requirement; such input fails with `ERR_INVALID_ISSUER_SIGNED_ITEM`
7. Credential `docType` matches MSO `docType` (legacy shapes). Shape C still uses only `documents[0]` (spike: multi-doc later)
8. For mDL: if `issuing_country` is disclosed (including `""`) it must match DS `C`; `issuing_jurisdiction` matches `ST` when both present. Values are compared raw (not RFC 4514 escaped); an unparseable DS subject → `ERR_INVALID_DS_CERT_SUBJECT`; `issue_date` (if disclosed) must be a valid full-date or tdate (compared by its UTC date) and not after `validFrom`
9. For mDL **when `mdocStrictProfile=true`** (`MdlDataElementValidator`, docType `org.iso.18013.5.1.mDL` only), all `ERR_INVALID_MDL_ELEMENT`:
   - ISO Table 5 types: `portrait` / `biometric_template_*` / `signature_usual_mark` bstr; `birth_date` full-date; `issue_date` / `expiry_date` full-date or tdate; `issuing_country` / `nationality` / `resident_country` ISO 3166-1 alpha-2 (`^[A-Z]{2}$`); `un_distinguishing_sign` 1–3 capital letters; `height`, `weight`, `sex`, `age_in_years`, `age_birth_year` uint; `age_over_NN` bool
   - Listed text fields (`family_name`, `given_name`, `resident_address`, ...) are printable Latin-1 (0x20–0x7E, 0xA0–0xFF; control characters rejected), ≤150 characters. `*_national_character` names allow full UTF-8
   - `driving_privileges` is an array (may be empty) of maps, each with a non-empty text `vehicle_category_code`, optional full-date `issue_date` / `expiry_date`, and optional non-empty `codes` whose entries have a text `code` and, if present, text `sign` / `value`. The detail is logged; the returned message is generic
   - Age claims vs `birth_date`, accepting the issuer's calculation at `signed` or `validFrom`: `age_over_NN = true` needs age at `validFrom` ≥ NN, `false` needs age at `signed` < NN, `age_in_years` must lie between the two ages. `birth_date` after `validFrom` is rejected; without `birth_date` nothing is checked
   - **Mandatory field presence only when the mDL namespace is fully disclosed** (every MSO digest for `org.iso.18013.5.1` is present in `nameSpaces`); missing identifiers are logged, not returned. Selective disclosure skips §3.4, so a non-conformant issuer's mDL that omits a mandatory field from the MSO still passes whenever the holder hides another element. This is a verifier-side limitation
   - Certify `portrait` is still text until inji-certify#1147 item 6

Use `CredentialsVerifier.verify(..., mdocStrictProfile = false)` to temporarily relax KeyUsage/EKU + §3 field checks for non-conformant Certify fixtures (issue #300).
`mdocStrictProfile` defaults to `true`, so Inji Verify and the wallet must pass `false` (through a config property set in every environment) until inji-certify#1132 (DS EKU) and inji-certify#1147 (field fixes) land.

## Out of scope

- IACA trust chain / CRL
- IACA ↔ DS `countryName` match
- ES384 / ES512 / EdDSA (vc-verifier#302)
- DeviceResponse / holder `deviceKey` presentation binding

## Release notes (behaviour and API changes)

- `LikelyTamperedException` (public) now takes `(errorMessage, errorCode)` (both defaulted) instead of `(message)`,
  and `CredentialsVerifier.verify` returns its code `ERR_LIKELY_TAMPERED`. Previously a tampered mDL reported
  `ERR_INVALID_VALUE_DIGESTS`, and an expired + tampered mDL reported `ERR_VC_EXPIRED`
- New error codes: `ERR_LIKELY_TAMPERED`, `ERR_INVALID_DS_CERT_SUBJECT`
- `signed` is now mandatory for shapes B and C, and `validFrom` ≥ `signed` applies to all shapes
- The non-ISO `valueDigests.nameSpaces` wrapper is rejected (`ERR_INVALID_MSO`)
- Only ES256 is accepted and the DS key must be EC P-256 (`ERR_INVALID_ALG`)
- MSO tag 24 and `tdate` tag 0 on `validityInfo` dates are now required for shapes B and C too
- An mDL past `validUntil` used to return `false` with `ERR_INVALID_VALID_UNTIL_MSO`. If everything else verifies,
  it now returns `true` with `ERR_VC_EXPIRED`; Inji Verify and the wallet should show it as "expired", not "valid".
  `ERR_INVALID_VALID_UNTIL_MSO` now means only a badly formatted `validUntil`
- `issue_date` / `expiry_date` accept tdate as well as full-date
- `Util.calculateDigest` was removed (no longer used)
- Strict mDL field checks are tighter: country codes must be alpha-2, text fields reject control characters,
  `driving_privileges` code `sign` / `value` must be text, and age claims accept either `signed` or `validFrom` as the calculation time
- The missing-mandatory-element message no longer lists the identifiers (they are logged)
- `MsoMdocVerificationOptions` gains `currentTimeMillis`; `MsoMdocCredentialData.IssuerSigned.encodedNameSpaceItems` no longer has a default

## Error codes

See `CredentialValidatorConstants` and the **mso_mdoc Format VC Error Codes** table in
[`vc-verifier/kotlin/README.md`](../vc-verifier/kotlin/README.md).

## Test fixtures

ISO-conformant pass-path fixtures (DS EKU `1.0.18013.5.1.2`, mandatory mDL claims including
`issuing_country`) are tracked on the Certify side. Until they land, success-path verifier tests
remain `@Disabled`. Fail-path and structural validator tests run without those fixtures.
