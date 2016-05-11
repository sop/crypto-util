<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Hash;

use ASN1\Element;
use ASN1\Type\Primitive\NullType;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/**
 * Base class for HMAC algorithm identifiers specified in RFC 4231.
 *
 * @link https://tools.ietf.org/html/rfc4231#section-3.1
 */
abstract class RFC4231HMACAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	HashAlgorithmIdentifier, PRFAlgorithmIdentifier
{
	/**
	 * Parameters stored for re-encoding.
	 *
	 * @var NullType|null $_params
	 */
	protected $_params;
	
	protected static function _fromASN1Params(Element $params = null) {
		/*
		 * RFC 4231 states that the "parameter" component SHOULD be present
		 * but have type NULL.
		 */
		if (isset($params)) {
			$params->expectType(Element::TYPE_NULL);
		}
		$obj = new static();
		$obj->_params = $params;
		return $obj;
	}
	
	protected function _paramsASN1() {
		return $this->_params;
	}
}
