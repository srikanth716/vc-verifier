package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_AGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import java.math.BigInteger

class MdlDataElementValidatorTest {

    // ---- S3-1 element types ----

    @ParameterizedTest(name = "{0} = {1}")
    @MethodSource("wrongTypes")
    fun `should reject an mDL element of the wrong type`(identifier: String, value: DataItem) {
        assertInvalid { validateStrict(identifier to value) }
    }

    @ParameterizedTest(name = "{0} = {1}")
    @MethodSource("correctTypes")
    fun `should accept an mDL element of the right type`(identifier: String, value: DataItem) {
        assertDoesNotThrow { validateStrict(identifier to value) }
    }

    @Test
    fun `should not check types when checkTypesAndStructure is false`() {
        val elements = wrongTypes().map { it.get()[0] as String to it.get()[1] as DataItem }
            .distinctBy { it.first }
        assertDoesNotThrow {
            MdlDataElementValidator.validate(
                items = itemsOf(*elements.toTypedArray()),
                mso = CborMap(),
                checkTypesAndStructure = false,
                checkMandatoryPresence = false,
            )
        }
    }

    @Test
    fun `should ignore elements of other namespaces`() {
        val item = DecodedIssuerSignedItem("org.example", BigInteger.ZERO, "portrait", UnicodeString("text"))
        assertDoesNotThrow {
            MdlDataElementValidator.validate(listOf(item), CborMap(), checkTypesAndStructure = true, checkMandatoryPresence = false)
        }
    }

    // ---- S3-2 driving_privileges ----

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidDrivingPrivileges")
    fun `should reject invalid driving_privileges`(@Suppress("UNUSED_PARAMETER") case: String, value: DataItem) {
        val exception = assertInvalid { validateStrict("driving_privileges" to value) }
        assertEquals(ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES, exception.message)
    }

    @Test
    fun `should accept a full valid driving_privileges entry`() {
        val entry = privilege(
            "issue_date" to UnicodeString("2020-01-01"),
            "expiry_date" to UnicodeString("2030-01-01"),
            "codes" to CborArray().apply {
                add(
                    mapOf(
                        "code" to UnicodeString("S01"),
                        "sign" to UnicodeString("<="),
                        "value" to UnicodeString("3500"),
                    )
                )
            },
        )
        assertDoesNotThrow { validateStrict("driving_privileges" to arrayOf(entry)) }
    }

    @Test
    fun `should accept an empty driving_privileges array`() {
        assertDoesNotThrow { validateStrict("driving_privileges" to CborArray()) }
    }

    // ---- S3-3 Latin-1 text ----

    @ParameterizedTest
    @ValueSource(strings = ["Müller", "José", "O'Brien-Smith", "ÿ"])
    fun `should accept printable Latin-1 text`(text: String) {
        assertDoesNotThrow { validateStrict("family_name" to UnicodeString(text)) }
    }

    @Test
    fun `should accept text of exactly 150 characters`() {
        assertDoesNotThrow { validateStrict("family_name" to UnicodeString("a".repeat(150))) }
    }

    @ParameterizedTest
    @ValueSource(strings = ["日本", "Doe\n", "Do\u0000e", "Do\u007Fe", "Do\u0085e"])
    fun `should reject non-Latin-1 or control characters in family_name`(text: String) {
        assertInvalid { validateStrict("family_name" to UnicodeString(text)) }
    }

    @Test
    fun `should reject text of 151 characters`() {
        assertInvalid { validateStrict("family_name" to UnicodeString("a".repeat(151))) }
    }

    @Test
    fun `should apply the Latin-1 rule to other listed fields such as resident_address`() {
        assertInvalid { validateStrict("resident_address" to UnicodeString("1 Main St\u0000")) }
        assertInvalid { validateStrict("resident_address" to UnicodeString("x".repeat(151))) }
    }

    @Test
    fun `should allow full UTF-8 in national character names`() {
        assertDoesNotThrow { validateStrict("family_name_national_character" to UnicodeString("山田")) }
    }

    // ---- S3-4 mandatory elements ----

    @Test
    fun `should reject missing mandatory elements for a fully disclosed mDL namespace`() {
        val exception = assertInvalid {
            MdlDataElementValidator.validate(
                items = itemsOf("family_name" to UnicodeString("Doe")),
                mso = msoWithDigests(0),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
        // The missing identifiers are logged, not returned.
        assertEquals(ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT, exception.message)
    }

    @Test
    fun `should skip mandatory elements under selective disclosure`() {
        // MSO still has digest 1 undisclosed, so the mDL namespace is not fully disclosed (§3.4).
        assertDoesNotThrow {
            MdlDataElementValidator.validate(
                items = itemsOf("family_name" to UnicodeString("Doe")),
                mso = msoWithDigests(0, 1),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
    }

    @Test
    fun `should allow an empty disclosure when the MSO has undisclosed mDL digests`() {
        assertDoesNotThrow {
            MdlDataElementValidator.validate(
                items = emptyList(),
                mso = msoWithDigests(0),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
    }

    @Test
    fun `should reject an empty disclosure when the MSO has no mDL digests`() {
        assertInvalid {
            MdlDataElementValidator.validate(
                items = emptyList(),
                mso = CborMap(),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
    }

    @Test
    fun `should allow all mandatory elements for a fully disclosed mDL namespace`() {
        val requiredElements: List<Pair<String, DataItem>> = listOf(
            "family_name" to UnicodeString("Doe"),
            "given_name" to UnicodeString("Jane"),
            "birth_date" to UnicodeString("1990-01-01"),
            "issue_date" to UnicodeString("2024-01-01"),
            "expiry_date" to UnicodeString("2030-01-01"),
            "issuing_country" to UnicodeString("IN"),
            "issuing_authority" to UnicodeString("Authority"),
            "document_number" to UnicodeString("123456"),
            "portrait" to ByteString(byteArrayOf(1)),
            "driving_privileges" to arrayOf(privilege()),
            "un_distinguishing_sign" to UnicodeString("IND"),
        )
        assertDoesNotThrow {
            MdlDataElementValidator.validate(
                items = itemsOf(*requiredElements.toTypedArray()),
                mso = msoWithDigests(*requiredElements.indices.map { it.toLong() }.toLongArray()),
                checkTypesAndStructure = true,
                checkMandatoryPresence = true,
            )
        }
    }

    // ---- S3-5 age consistency ----

    @Test
    fun `should reject age_over inconsistent with birth_date`() {
        val exception = assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2010-01-01"),
                "age_over_18" to TRUE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
        assertEquals(ERROR_MESSAGE_INVALID_MDL_AGE, exception.message)
    }

    @Test
    fun `should accept consistent age_over_18 true and age_over_65 false`() {
        assertDoesNotThrow {
            validateStrict(
                "birth_date" to UnicodeString("2000-01-01"),
                "age_over_18" to TRUE,
                "age_over_65" to FALSE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [24])
    fun `should accept a matching age_in_years`(age: Long) {
        assertDoesNotThrow { validateAgeInYears(age) }
    }

    @ParameterizedTest
    @ValueSource(longs = [22, 23, 25, 26])
    fun `should reject an age_in_years outside the signed-validFrom window`(age: Long) {
        assertInvalid { validateAgeInYears(age) }
    }

    @Test
    fun `should not wrap an age_in_years above Int MAX_VALUE`() {
        // 2^32 + 24 would wrap to 24 with toInt().
        val huge = UnsignedInteger(BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(24)))
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2000-01-01"),
                "age_in_years" to huge,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ageClaimsAroundBirthday")
    fun `should accept age claims computed at signed or at validFrom when the birthday falls between`(
        identifier: String,
        value: DataItem,
    ) {
        // Turns 18 on 2024-01-10: 17 at signed, 18 at validFrom.
        assertDoesNotThrow {
            validateStrict(
                "birth_date" to UnicodeString("2006-01-10"),
                identifier to value,
                mso = msoWithValidity(signed = "2024-01-05T00:00:00Z", validFrom = "2024-01-15T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should still reject an age claim outside the window around a birthday`() {
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2006-01-10"),
                "age_in_years" to UnsignedInteger(19),
                mso = msoWithValidity(signed = "2024-01-05T00:00:00Z", validFrom = "2024-01-15T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should reject a birth_date after validFrom`() {
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2025-01-01"),
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should not check age_over_NN without birth_date`() {
        assertDoesNotThrow {
            validateStrict(
                "age_over_18" to FALSE,
                "age_over_99" to TRUE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    // ---- helpers ----

    private fun validateAgeInYears(age: Long) = validateStrict(
        "birth_date" to UnicodeString("2000-01-01"),
        "age_in_years" to UnsignedInteger(age),
        mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
    )

    private fun validateStrict(vararg elements: Pair<String, DataItem>, mso: CborMap = CborMap()) =
        MdlDataElementValidator.validate(
            items = itemsOf(*elements),
            mso = mso,
            checkTypesAndStructure = true,
            checkMandatoryPresence = false,
        )

    private fun assertInvalid(block: () -> Unit): ValidationException {
        val exception = assertThrows(ValidationException::class.java) { block() }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
        return exception
    }

    private fun itemsOf(vararg elements: Pair<String, DataItem>): List<DecodedIssuerSignedItem> =
        elements.mapIndexed { index, (identifier, value) ->
            DecodedIssuerSignedItem(MDL_NAMESPACE, BigInteger.valueOf(index.toLong()), identifier, value)
        }

    private fun msoWithDigests(vararg digestIds: Long): CborMap {
        val digestMap = CborMap().apply {
            digestIds.forEach { id -> put(UnsignedInteger(id), ByteString(ByteArray(32))) }
        }
        return CborMap().apply {
            put(UnicodeString(VALUE_DIGESTS), CborMap().apply { put(UnicodeString(MDL_NAMESPACE), digestMap) })
        }
    }

    private fun msoWithValidity(validFrom: String, signed: String = validFrom): CborMap =
        CborMap().apply {
            put(
                UnicodeString(VALIDITY_INFO),
                CborMap().apply {
                    put(UnicodeString(SIGNED), UnicodeString(signed).apply { setTag(0) })
                    put(UnicodeString("validFrom"), UnicodeString(validFrom).apply { setTag(0) })
                }
            )
        }

    companion object {
        private val TRUE = SimpleValue(SimpleValueType.TRUE)
        private val FALSE = SimpleValue(SimpleValueType.FALSE)

        private fun mapOf(vararg entries: Pair<String, DataItem>): CborMap =
            CborMap().apply { entries.forEach { (key, value) -> put(UnicodeString(key), value) } }

        private fun arrayOf(vararg items: DataItem): CborArray =
            CborArray().apply { items.forEach { add(it) } }

        private fun privilege(vararg extra: Pair<String, DataItem>): CborMap =
            mapOf("vehicle_category_code" to UnicodeString("A"), *extra)

        private fun args(vararg values: Any) = Arguments.of(*values)

        @JvmStatic
        fun wrongTypes() = listOf(
            args("portrait", UnicodeString("base64-portrait")), // today's Certify output, inji-certify#1147 item 6
            args("birth_date", UnicodeString("15/06/1990")),
            args("birth_date", UnicodeString("2024-02-30")),
            args("birth_date", UnicodeString("1990-06-15T00:00:00Z")),
            args("issue_date", UnicodeString("2024-02-30")),
            args("issue_date", UnsignedInteger(20240101)),
            args("expiry_date", UnicodeString("2030-01-01T00:00:00.000Z")),
            args("issuing_country", UnsignedInteger(356)),
            args("issuing_country", UnicodeString("India")),
            args("issuing_country", UnicodeString("in")),
            args("nationality", UnicodeString("IND")),
            args("un_distinguishing_sign", UnicodeString("INDIA")),
            args("un_distinguishing_sign", UnicodeString("")),
            args("issuing_jurisdiction", UnsignedInteger(1)),
            args("height", NegativeInteger(-1)),
            args("age_in_years", UnicodeString("30")),
            args("age_over_18", UnicodeString("true")),
            args("biometric_template_face", UnicodeString("template")),
            args("signature_usual_mark", UnicodeString("mark")),
            args("family_name", ByteString(byteArrayOf(1))),
        )

        @JvmStatic
        fun correctTypes() = listOf(
            args("portrait", ByteString(byteArrayOf(1, 2, 3))),
            args("birth_date", UnicodeString("1990-06-15")),
            args("issue_date", UnicodeString("2024-01-01")),
            args("issue_date", UnicodeString("2024-01-01T00:00:00Z")),
            args("expiry_date", UnicodeString("2030-01-01T00:00:00Z")),
            args("issuing_country", UnicodeString("IN")),
            args("resident_country", UnicodeString("DE")),
            args("un_distinguishing_sign", UnicodeString("IND")),
            args("un_distinguishing_sign", UnicodeString("D")),
            args("issuing_jurisdiction", UnicodeString("IN-KA")),
            args("height", UnsignedInteger(180)),
            args("age_over_18", TRUE),
            args("biometric_template_face", ByteString(byteArrayOf(1))),
            args("family_name", UnicodeString("Doe")),
            args("some_domestic_element", UnsignedInteger(1)),
        )

        @JvmStatic
        fun invalidDrivingPrivileges() = listOf(
            args("camelCase vehicleCategoryCode", arrayOf(mapOf("vehicleCategoryCode" to UnicodeString("A")))),
            args("a map instead of an array", privilege()),
            args("an entry that is not a map", arrayOf(UnicodeString("A"))),
            args("empty vehicle_category_code", arrayOf(mapOf("vehicle_category_code" to UnicodeString("")))),
            args("numeric vehicle_category_code", arrayOf(mapOf("vehicle_category_code" to UnsignedInteger(1)))),
            args("impossible issue_date", arrayOf(privilege("issue_date" to UnicodeString("2023-13-01")))),
            args("tdate issue_date", arrayOf(privilege("issue_date" to UnicodeString("2023-01-01T00:00:00Z")))),
            args("tdate expiry_date", arrayOf(privilege("expiry_date" to UnicodeString("2030-01-01T00:00:00Z")))),
            args("empty codes", arrayOf(privilege("codes" to CborArray()))),
            args("codes as a map", arrayOf(privilege("codes" to mapOf("code" to UnicodeString("S01"))))),
            args("code entry without code", arrayOf(privilege("codes" to arrayOf(mapOf("sign" to UnicodeString("=")))))),
            args(
                "numeric sign",
                arrayOf(privilege("codes" to arrayOf(mapOf("code" to UnicodeString("S01"), "sign" to UnsignedInteger(1))))),
            ),
            args(
                "numeric value",
                arrayOf(privilege("codes" to arrayOf(mapOf("code" to UnicodeString("S01"), "value" to UnsignedInteger(5))))),
            ),
        )

        @JvmStatic
        fun ageClaimsAroundBirthday() = listOf(
            args("age_over_18", TRUE),
            args("age_over_18", FALSE),
            args("age_in_years", UnsignedInteger(17)),
            args("age_in_years", UnsignedInteger(18)),
        )
    }
}
