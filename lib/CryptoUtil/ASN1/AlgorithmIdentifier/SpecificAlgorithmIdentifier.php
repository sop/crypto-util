<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier;

use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Base class for algorithm identifiers implementing specific functionality
 * and parameter handling.
 */
abstract class SpecificAlgorithmIdentifier extends AlgorithmIdentifier
{
	/**
	 * Initialize object from algorithm identifier parameters.
	 *
	 * @param UnspecifiedType|null $params Parameters or null if none
	 * @return self
	 */
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		throw new \BadMethodCallException(
			__FUNCTION__ . " must be implemented in derived class.");
	}
}
