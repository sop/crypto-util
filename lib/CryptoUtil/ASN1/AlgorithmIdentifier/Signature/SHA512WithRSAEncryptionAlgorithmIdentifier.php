<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;


/**
 *
 * @link https://tools.ietf.org/html/rfc4055#section-5
 */
class SHA512WithRSAEncryptionAlgorithmIdentifier extends RFC4055RSASignatureAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		parent::__construct();
		$this->_oid = self::OID_SHA512_WITH_RSA_ENCRYPTION;
	}
	
	/**
	 *
	 * @return string
	 */
	public function name() {
		return "sha512WithRSAEncryption";
	}
}
