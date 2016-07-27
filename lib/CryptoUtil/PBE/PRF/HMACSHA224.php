<?php

namespace CryptoUtil\PBE\PRF;


/**
 * Implements HMAC-SHA-224 as a pseudorandom function.
 */
class HMACSHA224 extends HMACPRF
{
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_length = 28;
	}
	
	protected function _hashAlgo() {
		return "sha224";
	}
}
