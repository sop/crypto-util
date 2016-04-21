<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/**
 * Base class for Password-Based Cryptography schemes.
 *
 * @link https://tools.ietf.org/html/rfc2898
 */
abstract class PBEAlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
	/**
	 * Salt
	 *
	 * @var string $_salt
	 */
	protected $_salt;
	
	/**
	 * Iteration count
	 *
	 * @var int $_iterationCount
	 */
	protected $_iterationCount;
	
	/**
	 * Constructor
	 *
	 * @param string $salt
	 * @param int $iteration_count
	 */
	public function __construct($salt, $iteration_count) {
		$this->_salt = $salt;
		$this->_iterationCount = $iteration_count;
	}
	
	/**
	 * Get salt
	 *
	 * @return string
	 */
	public function salt() {
		return $this->_salt;
	}
	
	/**
	 * Get iteration count
	 *
	 * @return int
	 */
	public function iterationCount() {
		return $this->_iterationCount;
	}
}
