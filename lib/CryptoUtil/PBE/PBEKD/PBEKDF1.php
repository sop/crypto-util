<?php

namespace CryptoUtil\PBE\PBEKD;

use CryptoUtil\PBE\HashFunc\HashFunc;


/**
 * Implements key derivation function #1 used in password-based cryptography.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-5.1
 */
class PBEKDF1 extends PBEKDF
{
	/**
	 * Hash functor.
	 *
	 * @var HashFunc $_hashFunc
	 */
	protected $_hashFunc;
	
	/**
	 * Constructor
	 *
	 * @param HashFunc $hashfunc
	 */
	public function __construct(HashFunc $hashfunc) {
		$this->_hashFunc = $hashfunc;
	}
	
	public function derive($password, $salt, $count, $length) {
		if ($length > $this->_hashFunc->length()) {
			throw new \LogicException("Derived key too long");
		}
		$key = $password . $salt;
		for ($i = 0; $i < $count; ++$i) {
			$key = $this->_hashFunc->__invoke($key);
		}
		return substr($key, 0, $length);
	}
}
