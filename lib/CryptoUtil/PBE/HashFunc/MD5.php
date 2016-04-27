<?php

namespace CryptoUtil\PBE\HashFunc;


/**
 * MD5 hash function.
 */
class MD5 extends HashFunc
{
	/**
	 * Constructor
	 */
	public function __construct() {
		$this->_length = 16;
	}
	
	public function hash($data) {
		return md5($data, true);
	}
}
