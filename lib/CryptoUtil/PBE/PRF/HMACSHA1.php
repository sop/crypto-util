<?php

namespace CryptoUtil\PBE\PRF;


/**
 * Implements HMAC-SHA-1 as a pseudorandom function.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-B.1.1
 */
class HMACSHA1 extends PRF
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_length = 20;
	}
	
	public function compute($arg1, $arg2) {
		return hash_hmac("sha1", $arg2, $arg1, true);
	}
}
