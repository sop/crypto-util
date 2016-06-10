<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Feature;

use ASN1\Type\Constructed\Sequence;


/**
 * Base interface for algorithm identifiers.
 */
interface AlgorithmIdentifierType
{
	/**
	 * Get the object identifier of the algorithm.
	 *
	 * @return string
	 */
	public function oid();
	
	/**
	 * Get a human readable name of the algorithm.
	 *
	 * @return string
	 */
	public function name();
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1();
}
