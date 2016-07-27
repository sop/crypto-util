<?php

namespace CryptoUtil\PBE\PRF;


/**
 * Implements HMAC-SHA-512 as a pseudorandom function.
 */
class HMACSHA512 extends HMACPRF
{
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_length = 64;
	}
	
	protected function _hashAlgo() {
		return "sha512";
	}
}
