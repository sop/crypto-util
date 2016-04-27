<?php

namespace CryptoUtil\PBE\HashFunc;


/**
 * Base class for hash functions used in password-based cryptography.
 */
abstract class HashFunc
{
	/**
	 * Length of the produced hash in bytes.
	 *
	 * @var int $_length
	 */
	protected $_length;
	
	/**
	 * Hash function
	 *
	 * @param string $data
	 * @return string Hash result in raw format
	 */
	abstract public function hash($data);
	
	/**
	 * Functor interface.
	 *
	 * @param string $data
	 * @return string
	 */
	public function __invoke($data) {
		return $this->hash($data);
	}
	
	/**
	 * Get hash length.
	 *
	 * @return int
	 */
	public function length() {
		return $this->_length;
	}
}
