<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;


/**
 * Base class for block cipher algorithm identifiers.
 */
abstract class BlockCipherAlgorithmIdentifier extends CipherAlgorithmIdentifier
{
	/**
	 * Get block size in bytes.
	 *
	 * @return int
	 */
	abstract public function blockSize();
}
