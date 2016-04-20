<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\BlockCipherAlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Primitive\OctetString;


/**
 *
 * @link http://www.alvestrand.no/objectid/1.3.14.3.2.7.html
 * @link http://www.oid-info.com/get/1.3.14.3.2.7
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
		$iv = null;
		if (isset($params)) {
			$iv = $params->expectType(Element::TYPE_OCTET_STRING)->str();
		}
		return new self($iv);
	}
	
	protected function _paramsASN1() {
		return isset($this->_initializationVector) ? new OctetString(
			$this->_initializationVector) : null;
	}
	
	public function blockSize() {
		return 8;
	}
	
	public function keySize() {
		return 8;
	}
}
