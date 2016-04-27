<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Feature;


/**
 * Base interface for algorithm identifiers.
 */
interface AlgorithmIdentifierType
{
	/**
	 * Get object identifier.
	 *
	 * @return string
	 */
	public function oid();
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1();
}
