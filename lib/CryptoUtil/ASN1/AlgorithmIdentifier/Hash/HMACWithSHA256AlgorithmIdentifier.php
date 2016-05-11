<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Hash;


/**
 * HMAC with SHA-256 algorithm identifier.
 *
 * @link https://tools.ietf.org/html/rfc4231#section-3.1
 */
class HMACWithSHA256AlgorithmIdentifier extends RFC4231HMACAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_HMAC_WITH_SHA256;
	}
}
