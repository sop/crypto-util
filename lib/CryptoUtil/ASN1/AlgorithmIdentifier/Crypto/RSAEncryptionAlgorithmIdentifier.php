<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Crypto;

use ASN1\Element;
use ASN1\Type\Primitive\NullType;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 3447:

    When rsaEncryption is used in an AlgorithmIdentifier the
    parameters MUST be present and MUST be NULL.

*//* @formatter:on */

/**
 * RSA Encryption
 *
 * @link http://www.oid-info.com/get/1.2.840.113549.1.1.1
 * @link https://tools.ietf.org/html/rfc3447#appendix-C
 */
class RSAEncryptionAlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_RSA_ENCRYPTION;
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		return new self();
	}
	
	protected function _paramsASN1() {
		return new NullType();
	}
}
