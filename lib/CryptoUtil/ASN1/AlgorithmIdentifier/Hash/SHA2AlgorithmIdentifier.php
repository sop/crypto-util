<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Hash;

use ASN1\Type\Primitive\NullType;
use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 5754 - 2. Message Digest Algorithms

    The AlgorithmIdentifier parameters field is OPTIONAL.
    Implementations MUST accept SHA2 AlgorithmIdentifiers with absent
    parameters.  Implementations MUST accept SHA2 AlgorithmIdentifiers
    with NULL parameters.  Implementations MUST generate SHA2
    AlgorithmIdentifiers with absent parameters.

*//* @formatter:on */

/**
 * Base class for SHA2 algorithm identifiers.
 *
 * @link https://tools.ietf.org/html/rfc4055#section-2.1
 * @link https://tools.ietf.org/html/rfc5754#section-2
 */
abstract class SHA2AlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	HashAlgorithmIdentifier
{
	/**
	 * Parameters.
	 *
	 * @var NullType|null $_params
	 */
	protected $_params;
	
	public function __construct() {
		$this->_params = null;
	}
	
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		$obj = new static();
		// if parameters field is present, it must be null type
		if (isset($params)) {
			$obj->_params = $params->asNull();
		}
		return $obj;
	}
	
	protected function _paramsASN1() {
		return $this->_params;
	}
}
