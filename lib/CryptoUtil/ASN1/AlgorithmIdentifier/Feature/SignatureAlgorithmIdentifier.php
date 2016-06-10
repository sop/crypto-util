<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Feature;

use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Algorithm identifier for signature algorithms.
 */
interface SignatureAlgorithmIdentifier extends AlgorithmIdentifierType
{
	/**
	 * Check whether signature algorithm supports given key algorithm.
	 *
	 * @param AlgorithmIdentifier $algo
	 * @return bool
	 */
	public function supportsKeyAlgorithm(AlgorithmIdentifier $algo);
}
