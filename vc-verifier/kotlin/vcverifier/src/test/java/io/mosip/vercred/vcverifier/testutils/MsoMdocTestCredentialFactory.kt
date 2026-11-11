package testutils

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.Date

/**
 * Builds signed mso_mdoc credentials (and DS certificates) for tests, so verification can be
 * exercised through the public API with any validity window, certificate profile or tampering.
 */
internal object MsoMdocTestCredentialFactory {
    const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
    const val MDL_NAMESPACE = "org.iso.18013.5.1"
    const val MDL_DS_EKU = "1.0.18013.5.1.2"
    const val DEFAULT_SUBJECT = "C=IN,ST=KA,O=vc-verifier test"
    val DEFAULT_CERT_NOT_BEFORE: Instant = Instant.parse("2020-01-01T00:00:00Z")
    val DEFAULT_CERT_NOT_AFTER: Instant = Instant.parse("2036-01-01T00:00:00Z")

    /** A = OpenID4VCI 1.0 IssuerSigned, B = docType + issuerSigned, C = documents[]. */
    enum class Shape { LATEST, ISSUER_SIGNED, DOCUMENTS }

    fun create(
        legacyShape: Boolean = false,
        shape: Shape = if (legacyShape) Shape.ISSUER_SIGNED else Shape.LATEST,
        includeKeyUsage: Boolean = true,
        certificate: X509Certificate? = null,
        now: Instant = Instant.now(),
        signed: Instant? = now.minusSeconds(120),
        validFrom: Instant = now.minusSeconds(60),
        validUntil: Instant = now.plusSeconds(365L * 24 * 60 * 60),
        topLevelDocType: String? = MDL_DOC_TYPE,
        msoDocType: String = MDL_DOC_TYPE,
        omitDigestId: Long? = null,
        records: List<Pair<String, DataItem>> = mandatoryRecords(validFrom),
        extraNamespaces: Map<String, List<Pair<String, DataItem>>> = emptyMap(),
        namespacesWithoutDigests: Set<String> = emptySet(),
        discloseOnly: Set<String>? = null,
        tamperedElement: Pair<String, DataItem>? = null,
        longFormItemHeaders: Boolean = false,
    ): String {
        val privateKey = loadPrivateKey()
        val dsCertificate = certificate ?: loadCertificate(includeKeyUsage)

        val allNamespaces = linkedMapOf(MDL_NAMESPACE to records).apply { putAll(extraNamespaces) }
        val disclosedItems = linkedMapOf<String, List<ByteArray>>()
        val valueDigests = CborMap()
        allNamespaces.forEach { (namespace, namespaceRecords) ->
            val wireItems = mutableListOf<ByteArray>()
            val digestMap = CborMap()
            namespaceRecords.forEachIndexed { index, (identifier, value) ->
                val digestId = index.toLong()
                val wireBytes = issuerSignedItemBytes(digestId, index, identifier, value, longFormItemHeaders)
                if (!(namespace == MDL_NAMESPACE && digestId == omitDigestId)) {
                    digestMap.put(
                        UnsignedInteger(digestId),
                        ByteString(MessageDigest.getInstance("SHA-256").digest(wireBytes))
                    )
                }
                // discloseOnly selects which mDL-namespace elements are sent; other namespaces are sent in full.
                if (discloseOnly == null || namespace != MDL_NAMESPACE || identifier in discloseOnly) {
                    // Tampering happens after the digest is computed, i.e. after issuer signing.
                    val sentBytes = if (tamperedElement?.first == identifier) {
                        issuerSignedItemBytes(digestId, index, identifier, tamperedElement.second, longFormItemHeaders)
                    } else {
                        wireBytes
                    }
                    wireItems.add(sentBytes)
                }
            }
            disclosedItems[namespace] = wireItems
            if (namespace !in namespacesWithoutDigests) {
                valueDigests.put(UnicodeString(namespace), digestMap)
            }
        }

        val mso = CborMap().apply {
            put(UnicodeString("version"), UnicodeString("1.0"))
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), valueDigests)
            put(UnicodeString("deviceKeyInfo"), CborMap())
            put(UnicodeString("docType"), UnicodeString(msoDocType))
            put(
                UnicodeString("validityInfo"),
                CborMap().apply {
                    signed?.let { put(UnicodeString("signed"), taggedDate(it)) }
                    put(UnicodeString("validFrom"), taggedDate(validFrom))
                    put(UnicodeString("validUntil"), taggedDate(validUntil))
                }
            )
        }
        val payload = encode(ByteString(encode(mso)).apply { setTag(24) })
        val protectedHeader = encode(
            CborMap().apply { put(UnsignedInteger(1), NegativeInteger(-7)) }
        )
        val issuerAuth = CborArray().apply {
            add(ByteString(protectedHeader))
            add(
                CborMap().apply {
                    put(UnsignedInteger(33), ByteString(dsCertificate.encoded))
                }
            )
            add(ByteString(payload))
            add(ByteString(sign(privateKey, protectedHeader, payload)))
        }

        val credential = assembleCredential(shape, topLevelDocType, encode(issuerAuth), disclosedItems)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(credential)
    }

    /** Self-signed DS certificate over the fixture DS key, with a configurable profile. */
    fun generateCertificate(
        notBefore: Instant = DEFAULT_CERT_NOT_BEFORE,
        notAfter: Instant = DEFAULT_CERT_NOT_AFTER,
        subject: String = DEFAULT_SUBJECT,
        keyUsage: Int? = KeyUsage.digitalSignature,
        keyUsageCritical: Boolean = true,
        ekuOid: String? = MDL_DS_EKU,
        ekuCritical: Boolean = true,
    ): X509Certificate {
        val name = X500Name(subject)
        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore),
            Date.from(notAfter),
            name,
            loadCertificate(includeKeyUsage = true).publicKey,
        )
        keyUsage?.let { builder.addExtension(Extension.keyUsage, keyUsageCritical, KeyUsage(it)) }
        ekuOid?.let {
            builder.addExtension(
                Extension.extendedKeyUsage,
                ekuCritical,
                ExtendedKeyUsage(KeyPurposeId.getInstance(ASN1ObjectIdentifier(it)))
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(loadPrivateKey())
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    fun mandatoryRecords(validFrom: Instant = Instant.now()): List<Pair<String, DataItem>> {
        // issue_date must not be after validFrom (UTC date).
        val issueDate = validFrom.atZone(ZoneOffset.UTC).toLocalDate().minusDays(1)
        val fullDate = DateTimeFormatter.ISO_LOCAL_DATE
        return listOf(
            "family_name" to UnicodeString("Doe"),
            "given_name" to UnicodeString("Jane"),
            "birth_date" to UnicodeString("1990-01-01"),
            "issue_date" to UnicodeString(issueDate.format(fullDate)),
            "expiry_date" to UnicodeString(issueDate.plusYears(5).format(fullDate)),
            "issuing_country" to UnicodeString("IN"),
            "issuing_authority" to UnicodeString("Test Authority"),
            "document_number" to UnicodeString("A1234567"),
            "portrait" to ByteString(byteArrayOf(1, 2, 3)),
            "driving_privileges" to CborArray().apply {
                add(
                    CborMap().apply {
                        put(UnicodeString("vehicle_category_code"), UnicodeString("A"))
                        put(UnicodeString("issue_date"), UnicodeString(issueDate.format(fullDate)))
                        put(UnicodeString("expiry_date"), UnicodeString(issueDate.plusYears(5).format(fullDate)))
                    }
                )
            },
            "un_distinguishing_sign" to UnicodeString("IND"),
        )
    }

    /** Records with [identifier] replaced (or appended) by [value]. */
    fun recordsWith(identifier: String, value: DataItem, validFrom: Instant = Instant.now()) =
        mandatoryRecords(validFrom).filterNot { it.first == identifier } + (identifier to value)

    fun recordsWithout(identifier: String, validFrom: Instant = Instant.now()) =
        mandatoryRecords(validFrom).filterNot { it.first == identifier }

    /** Tag-24 IssuerSignedItemBytes as they go on the wire. */
    private fun issuerSignedItemBytes(
        digestId: Long,
        index: Int,
        identifier: String,
        value: DataItem,
        longFormHeader: Boolean,
    ): ByteArray {
        val item = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(digestId))
            put(UnicodeString("random"), ByteString(ByteArray(16) { (index + 1).toByte() }))
            put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
            put(UnicodeString("elementValue"), value)
        }
        val itemBytes = encode(item)
        if (!longFormHeader) {
            return encode(ByteString(itemBytes).apply { setTag(24) })
        }
        // d8 18 5a <4-byte length>: tag 24 + bstr with a non-canonical 32-bit length header.
        val header = byteArrayOf(0xd8.toByte(), 0x18, 0x5a) +
            java.nio.ByteBuffer.allocate(4).putInt(itemBytes.size).array()
        return header + itemBytes
    }

    /**
     * Writes the outer credential by hand so the nameSpaces items keep their exact wire bytes
     * (CborEncoder would re-encode long-form headers canonically).
     */
    private fun assembleCredential(
        shape: Shape,
        topLevelDocType: String?,
        issuerAuthBytes: ByteArray,
        namespaces: Map<String, List<ByteArray>>,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val issuerSigned = ByteArrayOutputStream().apply {
            write(header(5, 2))
            write(text("issuerAuth"))
            write(issuerAuthBytes)
            write(text("nameSpaces"))
            write(header(5, namespaces.size))
            namespaces.forEach { (namespace, items) ->
                write(text(namespace))
                write(header(4, items.size))
                items.forEach { write(it) }
            }
        }.toByteArray()
        val docTypeEntry = topLevelDocType?.let { text("docType") + text(it) } ?: ByteArray(0)
        val docTypeCount = if (topLevelDocType == null) 0 else 1
        when (shape) {
            Shape.LATEST -> out.write(issuerSigned)
            Shape.ISSUER_SIGNED -> {
                out.write(header(5, docTypeCount + 1))
                out.write(docTypeEntry)
                out.write(text("issuerSigned"))
                out.write(issuerSigned)
            }
            Shape.DOCUMENTS -> {
                out.write(header(5, 1))
                out.write(text("documents"))
                out.write(header(4, 1))
                out.write(header(5, docTypeCount + 1))
                out.write(docTypeEntry)
                out.write(text("issuerSigned"))
                out.write(issuerSigned)
            }
        }
        return out.toByteArray()
    }

    private fun header(major: Int, length: Int): ByteArray {
        val m = major shl 5
        return when {
            length < 24 -> byteArrayOf((m or length).toByte())
            length < 0x100 -> byteArrayOf((m or 24).toByte(), length.toByte())
            length < 0x10000 -> byteArrayOf((m or 25).toByte(), (length shr 8).toByte(), length.toByte())
            else -> byteArrayOf((m or 26).toByte()) + java.nio.ByteBuffer.allocate(4).putInt(length).array()
        }
    }

    private fun text(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return header(3, bytes.size) + bytes
    }

    private fun loadPrivateKey(): PrivateKey {
        val pem = readFixture("test_ds_key_pkcs8.pem")
        val encoded = pem.lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
        return KeyFactory.getInstance("EC").generatePrivate(
            PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded))
        )
    }

    private fun loadCertificate(includeKeyUsage: Boolean): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                ByteArrayInputStream(
                    readFixture(
                        if (includeKeyUsage) "test_ds_mdl.pem" else "test_ds_no_key_usage.pem"
                    ).toByteArray()
                )
            ) as X509Certificate

    private fun readFixture(name: String): String =
        MsoMdocTestCredentialFactory::class.java.getResourceAsStream("/mso_mdoc/$name")
            ?.bufferedReader()
            ?.use { it.readText() }
            ?: error("Missing mDL test fixture: $name")

    private fun taggedDate(value: Instant): DataItem =
        UnicodeString(DateTimeFormatter.ISO_INSTANT.format(value.truncatedTo(ChronoUnit.SECONDS)))
            .apply { setTag(0) }

    private fun encode(dataItem: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()

    private fun sign(privateKey: PrivateKey, protectedHeader: ByteArray, payload: ByteArray): ByteArray {
        val structure = CborArray().apply {
            add(UnicodeString("Signature1"))
            add(ByteString(protectedHeader))
            add(ByteString(ByteArray(0)))
            add(ByteString(payload))
        }
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(encode(structure))
        val derSignature = ASN1Sequence.getInstance(signer.sign())
        val r = (derSignature.getObjectAt(0) as ASN1Integer).positiveValue
        val s = (derSignature.getObjectAt(1) as ASN1Integer).positiveValue
        return fixedWidth(r) + fixedWidth(s)
    }

    private fun fixedWidth(value: BigInteger): ByteArray {
        val bytes = value.toByteArray().let {
            if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it
        }
        return ByteArray(32 - bytes.size) + bytes
    }
}
