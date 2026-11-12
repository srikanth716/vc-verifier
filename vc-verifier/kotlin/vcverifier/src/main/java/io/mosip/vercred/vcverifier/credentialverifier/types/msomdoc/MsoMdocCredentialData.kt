package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.util.logging.Logger


typealias IssuerAuth = Array?
typealias IssuerSignedNamespaces = Map

private val logger = Logger.getLogger(MsoMdocCredentialData::class.java.name)


fun IssuerSignedNamespaces.extractFieldValue(fieldToBeExtracted: String): String {
    return extractFieldValue(fieldToBeExtracted, namespaceFilter = null) ?: ""
}

/**
 * Assumes [this] has passed MsoMdocVerifier.verifyValueDigests (every item a tag-24 bstr holding
 * an IssuerSignedItem map with a text elementIdentifier). Items that are not byte strings are skipped.
 */
fun IssuerSignedNamespaces.extractFieldValue(
    fieldToBeExtracted: String,
    namespaceFilter: String?,
): String? {
    val issuerSignedNamespacedData = this
    issuerSignedNamespacedData.keys.forEach { namespace ->
        if (namespaceFilter != null && (namespace as? UnicodeString)?.string != namespaceFilter) {
            return@forEach
        }
        val namespaceData: List<DataItem> =
            ((issuerSignedNamespacedData[namespace]) as Array).dataItems

        namespaceData.forEach { issuerSignedItem ->
            if (issuerSignedItem !is ByteString) {
                return@forEach
            }
            val decodedIssuerSignedItem =
                CborDecoder(ByteArrayInputStream(issuerSignedItem.bytes)).decode()[0] as Map
            val elementIdentifier: String =
                ((decodedIssuerSignedItem[ELEMENT_IDENTIFIER]) as UnicodeString).string

            if (elementIdentifier == fieldToBeExtracted) {
                val elementValue = decodedIssuerSignedItem[ELEMENT_VALUE]
                return when (elementValue) {
                    is UnicodeString -> elementValue.string
                    else -> elementValue?.toString()
                }
            }
        }
    }
    return null
}

/** One received IssuerSignedItem, decoded once by MsoMdocVerifier.verifyValueDigests and reused by later checks. */
internal data class DecodedIssuerSignedItem(
    val namespace: String,
    val digestId: BigInteger,
    val elementIdentifier: String,
    val elementValue: DataItem,
)

/**
 * Value of [identifier] in [namespace] as text (a tstr's content, otherwise its toString()),
 * or null when the element is not disclosed. Same conversion as [extractFieldValue].
 */
internal fun List<DecodedIssuerSignedItem>.elementText(identifier: String, namespace: String): String? {
    val value = firstOrNull { it.namespace == namespace && it.elementIdentifier == identifier }
        ?.elementValue
        ?: return null
    return (value as? UnicodeString)?.string ?: value.toString()
}

fun IssuerAuth.extractMso(): Map {
    if (this == null) {
        logger.severe("IssuerAuth in credential is not available")
        throw RuntimeException("Invalid Issuer Auth")
    }

    // Only the ISO form is accepted: #6.24(bstr .cbor MobileSecurityObject).
    val payload = CborDecoder.decode((this[2] as ByteString).bytes)[0]
    if (payload !is ByteString || payload.tag?.value != TAG_ENCODED_CBOR) {
        throw RuntimeException("Invalid Issuer Auth")
    }
    return CborDecoder.decode(payload.bytes)[0] as? Map
        ?: throw RuntimeException("Invalid Issuer Auth")
}

data class MsoMdocCredentialData(val docType: DataItem?, val issuerSigned: IssuerSigned, val mso: Map) {
    /**
     * @param encodedNameSpaceItems exact on-the-wire CBOR bytes for each nameSpaces array
     * element (full tag-24 IssuerSignedItemBytes), keyed by namespace string and aligned
     * with the decoded [namespaces] array order.
     */
    data class IssuerSigned(
        val issuerAuth: IssuerAuth,
        val namespaces: IssuerSignedNamespaces,
        val encodedNameSpaceItems: kotlin.collections.Map<String, List<ByteArray>>,
    )
}

