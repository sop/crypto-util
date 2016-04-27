<?php

namespace CryptoUtil\PBE\HashFunc;


/**
 * SHA1 hash function.
 */
class SHA1 extends HashFunc
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_length = 20;
	}
	
	public function hash($data) {
		return sha1($data, true);
	}
}
