<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier;

use ASN1\Element;
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
	 * @param Element|null $params Parameters or null if none
	 * @return self
	 */
	protected static function _fromASN1Params(Element $params = null) {
		// @codeCoverageIgnoreStart
		throw new \BadMethodCallException(
			__METHOD__ . " must be implemented in derived class.");
		// @codeCoverageIgnoreEnd
	}
}
