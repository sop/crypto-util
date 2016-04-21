<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;


class PBEWithMD5AndDESCBCAlgorithmIdentifier extends PBES1AlgorithmIdentifier
{
	public function __construct($salt, $iteration_count) {
		parent::__construct($salt, $iteration_count);
		$this->_oid = self::OID_PBE_WITH_MD5_AND_DES_CBC;
	}
}
