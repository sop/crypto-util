<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Hash;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use ASN1\Element;


/* @formatter:off *//*

Per RFC 2898 this algorithm identifier has no parameters:

algid-hmacWithSHA1 AlgorithmIdentifier {{PBKDF2-PRFs}} ::=
    {algorithm id-hmacWithSHA1, parameters NULL : NULL}

*//* @formatter:on */

/**
 *
 * @link http://www.alvestrand.no/objectid/1.2.840.113549.2.7.html
 * @link http://www.oid-info.com/get/1.2.840.113549.2.7
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 */
class HMACWithSHA1AlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	HashAlgorithmIdentifier, PRFAlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_oid = self::OID_HMAC_WITH_SHA1;
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		return new self();
	}
	
	protected function _paramsASN1() {
		return null;
	}
}
