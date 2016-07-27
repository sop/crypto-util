<?php

namespace CryptoUtil\PBE\PRF;


/**
 * Implements HMAC-SHA-256 as a pseudorandom function.
 */
class HMACSHA256 extends HMACPRF
{
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_length = 32;
	}
	
	protected function _hashAlgo() {
		return "sha256";
	}
}
