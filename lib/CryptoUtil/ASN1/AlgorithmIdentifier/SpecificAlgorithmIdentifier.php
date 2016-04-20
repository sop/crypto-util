<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier;

use CryptoUtil\ASN1\AlgorithmIdentifier;
use ASN1\Element;


/**
 * Base class for algorithm identifiers implementing specific
 * functionality and parameter handling.
 */
abstract class SpecificAlgorithmIdentifier extends AlgorithmIdentifier
{
	/**
	 * Initialize object from algorithm identifier parameters
	 *
	 * @param Element|null $params Parameters or null if none
	 * @return self
	 */
	protected static function _fromASN1Params(Element $params = null) {
		throw new \BadMethodCallException();
	}
}
