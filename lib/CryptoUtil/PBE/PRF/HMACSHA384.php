<?php

namespace CryptoUtil\PBE\PRF;


/**
 * Implements HMAC-SHA-384 as a pseudorandom function.
 */
class HMACSHA384 extends HMACPRF
{
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_length = 48;
	}
	
	protected function _hashAlgo() {
		return "sha384";
	}
}
