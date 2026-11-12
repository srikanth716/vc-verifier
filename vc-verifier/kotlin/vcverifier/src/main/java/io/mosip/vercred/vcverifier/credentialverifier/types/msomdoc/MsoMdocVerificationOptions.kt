package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

/**
 * Options for mso_mdoc / mDL verification.
 *
 * [strictMdlProfile] (default true) enforces issue #300 §1.2 (mDL DS KeyUsage/EKU) and §3.1 (mDL
 * element types). It relaxes nothing else: §3.2–§3.5 always run. Set false temporarily for
 * non-conformant Certify credentials until inji-certify#1132 (DS EKU) and inji-certify#1147
 * (element types, e.g. `portrait` as bytes) are closed; then remove the flag.
 *
 * [currentTimeMillis] supplies "now" for every mdoc time check (DS certificate validity,
 * validFrom / signed not in the future, validUntil expiry). Injectable so tests can pin the clock.
 */
data class MsoMdocVerificationOptions(
    val strictMdlProfile: Boolean = true,
    val currentTimeMillis: () -> Long = System::currentTimeMillis,
)

/** Clock-skew tolerance applied leniently to every mdoc comparison against "now". */
internal const val MDOC_CLOCK_SKEW_TOLERANCE_MS = 3000L

internal object MdocClock {
    /** True when [instantMillis] is in the future beyond the tolerance (now + tol < instant). */
    fun isAfterNow(instantMillis: Long, nowMillis: Long): Boolean =
        nowMillis + MDOC_CLOCK_SKEW_TOLERANCE_MS < instantMillis

    /** True when [instantMillis] is in the past beyond the tolerance (now - tol > instant). */
    fun isBeforeNow(instantMillis: Long, nowMillis: Long): Boolean =
        nowMillis - MDOC_CLOCK_SKEW_TOLERANCE_MS > instantMillis
}
