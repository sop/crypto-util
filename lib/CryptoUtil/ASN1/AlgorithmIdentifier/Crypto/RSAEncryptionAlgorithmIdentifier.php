<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Crypto;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Primitive\NullType;


/**
 * RSA Encryption
 *
 * @link http://www.oid-info.com/get/1.2.840.113549.1.1.1
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
