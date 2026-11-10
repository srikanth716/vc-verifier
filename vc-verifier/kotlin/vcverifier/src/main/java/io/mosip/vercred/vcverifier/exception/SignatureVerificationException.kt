package io.mosip.vercred.vcverifier.exception

class SignatureVerificationException @JvmOverloads constructor(
    message: String?,
    val errorCode: String? = null
) : BaseUncheckedException(message)