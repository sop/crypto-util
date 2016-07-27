<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;


/**
 * Algorithm identifier for AES with 256-bit key in CBC mode.
 *
 * @link https://tools.ietf.org/html/rfc3565.html#section-4.1
 * @link http://www.alvestrand.no/objectid/2.16.840.1.101.3.4.1.42.html
 * @link http://www.oid-info.com/get/2.16.840.1.101.3.4.1.42
 */
class AES256CBCAlgorithmIdentifier extends AESCBCAlgorithmIdentifier
{
	/**
	 * Constructor.
	 *
	 * @param string|null $iv Initialization vector
	 */
	public function __construct($iv = null) {
		$this->_oid = self::OID_AES_256_CBC;
		parent::__construct($iv);
	}
	
	/**
	 *
	 * @return string
	 */
	public function name() {
		return "aes256-CBC";
	}
	
	/**
	 *
	 * @return int
	 */
	public function keySize() {
		return 32;
	}
}
