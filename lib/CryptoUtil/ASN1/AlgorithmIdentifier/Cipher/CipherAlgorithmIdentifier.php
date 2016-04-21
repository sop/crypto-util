<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/**
 * Base class for cipher algorithm identifiers.
 */
abstract class CipherAlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
	/**
	 * Initialization vector
	 *
	 * @var string|null $_initializationVector
	 */
	protected $_initializationVector;
	
	/**
	 * Get key size in bytes
	 *
	 * @return int
	 */
	abstract public function keySize();
	
	/**
	 * Get initialization vector
	 *
	 * @return string|null
	 */
	public function initializationVector() {
		return $this->_initializationVector;
	}
	
	/**
	 * Get copy of the object with given initialization vector
	 *
	 * @param string|null $iv
	 * @return self
	 */
	public function withInitializationVector($iv) {
		$obj = clone $this;
		$obj->_initializationVector = $iv;
		return $obj;
	}
}
