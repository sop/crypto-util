<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use ASN1\Type\Primitive\OctetString;
use ASN1\Type\UnspecifiedType;


/* @formatter:off *//*

RFC 2898 defines parameters as follows:

{OCTET STRING (SIZE(8)) IDENTIFIED BY des-EDE3-CBC}

*//* @formatter:on */

/**
 * Algorithm identifier for Triple-DES cipher in CBC mode.
 *
 * @link http://www.alvestrand.no/objectid/1.2.840.113549.3.7.html
 * @link http://oid-info.com/get/1.2.840.113549.3.7
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 * @link https://tools.ietf.org/html/rfc2630#section-12.4.1
 */
class DESEDE3CBCAlgorithmIdentifier extends BlockCipherAlgorithmIdentifier
{
	/**
	 * Constructor
	 *
	 * @param string|null $iv Initialization vector
	 */
	public function __construct($iv = null) {
		$this->_checkIVSize($iv);
		$this->_oid = self::OID_DES_EDE3_CBC;
		$this->_initializationVector = $iv;
	}
	
	/**
	 *
	 * @return string
	 */
	public function name() {
		return "des-EDE3-CBC";
	}
	
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters.");
		}
		$iv = $params->asOctetString()->string();
		return new self($iv);
	}
	
	protected function _paramsASN1() {
		if (!isset($this->_initializationVector)) {
			throw new \LogicException("IV not set.");
		}
		return new OctetString($this->_initializationVector);
	}
	
	public function blockSize() {
		return 8;
	}
	
	public function keySize() {
		return 24;
	}
	
	public function ivSize() {
		return 8;
	}
}
