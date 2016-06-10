<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Crypto;

use ASN1\Type\Primitive\NullType;
use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 3447:

    When rsaEncryption is used in an AlgorithmIdentifier the
    parameters MUST be present and MUST be NULL.

*//* @formatter:on */

/**
 * Algorithm identifier for RSA encryption.
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
	
	/**
	 *
	 * @return string
	 */
	public function name() {
		return "rsaEncryption";
	}
	
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters.");
		}
		$params->asNull();
		return new self();
	}
	
	protected function _paramsASN1() {
		return new NullType();
	}
}
