<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Hash;

use ASN1\Type\Primitive\NullType;
use ASN1\Type\UnspecifiedType;
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
	
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		/*
		 * RFC 4231 states that the "parameter" component SHOULD be present
		 * but have type NULL.
		 */
		$obj = new static();
		if (isset($params)) {
			$obj->_params = $params->asNull();
		}
		return $obj;
	}
	
	protected function _paramsASN1() {
		return $this->_params;
	}
}
