<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;


/**
 * Algorithm identifier for password-based encryption scheme with SHA-1 and DES.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithSHA1AndDESCBCAlgorithmIdentifier extends PBES1AlgorithmIdentifier
{
	/**
	 * Constructor
	 *
	 * @param string $salt Salt
	 * @param int $iteration_count Iteration count
	 */
	public function __construct($salt, $iteration_count) {
		parent::__construct($salt, $iteration_count);
		$this->_oid = self::OID_PBE_WITH_SHA1_AND_DES_CBC;
	}
}
