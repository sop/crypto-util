<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;


class PBEWithSHA1AndDESCBCAlgorithmIdentifier extends PBES1AlgorithmIdentifier
{
	public function __construct($salt, $iteration_count) {
		parent::__construct($salt, $iteration_count);
		$this->_oid = self::OID_PBE_WITH_SHA1_AND_DES_CBC;
	}
}
