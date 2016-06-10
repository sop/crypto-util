<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;


/**
 * Signature algorithm with MD4 and RSA encryption.
 *
 * @link https://tools.ietf.org/html/rfc2313#section-11
 */
class MD4WithRSAEncryptionAlgorithmIdentifier extends RFC3279RSASignatureAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_MD4_WITH_RSA_ENCRYPTION;
	}
	
	/**
	 *
	 * @return string
	 */
	public function name() {
		return "md4withRSAEncryption";
	}
}
