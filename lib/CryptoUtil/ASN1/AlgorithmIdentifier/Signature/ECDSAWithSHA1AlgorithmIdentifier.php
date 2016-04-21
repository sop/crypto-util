<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;


/**
 *
 * @link https://tools.ietf.org/html/rfc3279#section-2.2.3
 */
class ECDSAWithSHA1AlgorithmIdentifier extends ECSignatureAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_ECDSA_WITH_SHA1;
	}
}
