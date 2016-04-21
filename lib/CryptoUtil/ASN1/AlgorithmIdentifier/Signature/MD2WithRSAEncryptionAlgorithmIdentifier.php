<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;


/**
 *
 * @link https://tools.ietf.org/html/rfc3279#section-2.2.1
 */
class MD2WithRSAEncryptionAlgorithmIdentifier extends RSASignatureAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_MD2_WITH_RSA_ENCRYPTION;
	}
}
