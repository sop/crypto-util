<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Feature;


/**
 * Algorithm identifier for block ciphers
 */
interface BlockCipherAlgorithmIdentifier
{
	/**
	 * Get block size in bytes
	 *
	 * @return int
	 */
	public function blockSize();
	
	/**
	 * Get key size in bytes
	 *
	 * @return int
	 */
	public function keySize();
}
