<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;


/**
 * Signature algorithm with MD2 and RSA encryption.
 *
 * @link https://tools.ietf.org/html/rfc3279#section-2.2.1
 */
class MD2WithRSAEncryptionAlgorithmIdentifier extends RFC3279RSASignatureAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_MD2_WITH_RSA_ENCRYPTION;
	}
}
