<?php

namespace CryptoUtil\PBE\PRF;

use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Base class for pseudorandom functions used in password-based cryptography.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-B.1
 */
abstract class PRF
{
	/**
	 * Length of the produced output in bytes.
	 *
	 * @var int $_length
	 */
	protected $_length;
	
	/**
	 * Compute pseudorandom value from arguments.
	 *
	 * @param string $arg1 First argument
	 * @param string $arg2 Second argument
	 * @return string Output
	 */
	abstract public function compute($arg1, $arg2);
	
	/**
	 * Functor interface.
	 *
	 * @param string $arg1
	 * @param string $arg2
	 * @return string
	 */
	public function __invoke($arg1, $arg2) {
		return $this->compute($arg1, $arg2);
	}
	
	/**
	 * Get output length.
	 *
	 * @return int
	 */
	public function length() {
		return $this->_length;
	}
	
	/**
	 * Get PRF by algorithm identifier.
	 *
	 * @param PRFAlgorithmIdentifier $algo
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromAlgorithmIdentifier(PRFAlgorithmIdentifier $algo) {
		switch ($algo->oid()) {
		case AlgorithmIdentifier::OID_HMAC_WITH_SHA1:
			return new HMACSHA1();
		}
		throw new \UnexpectedValueException(
			"PRF algorithm " . $algo->oid() . " not supported.");
	}
}
