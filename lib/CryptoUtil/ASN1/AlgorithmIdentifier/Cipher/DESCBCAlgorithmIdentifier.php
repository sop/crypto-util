<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use ASN1\Element;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\BlockCipherAlgorithmIdentifier;


/* @formatter:off *//*

RFC 2898 defines parameters as follows:

{OCTET STRING (SIZE(8)) IDENTIFIED BY desCBC}

*//* @formatter:on */

/**
 *
 * @link http://www.alvestrand.no/objectid/1.3.14.3.2.7.html
 * @link http://www.oid-info.com/get/1.3.14.3.2.7
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 */
class DESCBCAlgorithmIdentifier extends CipherAlgorithmIdentifier implements 
	BlockCipherAlgorithmIdentifier
{
	/**
	 * Constructor
	 *
	 * @param string|null $iv
	 */
	public function __construct($iv = null) {
		$this->_oid = self::OID_DES_CBC;
		$this->_initializationVector = $iv;
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters");
		}
		$iv = $params->expectType(Element::TYPE_OCTET_STRING)->str();
		return new self($iv);
	}
	
	protected function _paramsASN1() {
		if (!isset($this->_initializationVector)) {
			throw new \LogicException("IV not set");
		}
		return new OctetString($this->_initializationVector);
	}
	
	public function blockSize() {
		return 8;
	}
	
	public function keySize() {
		return 8;
	}
}
