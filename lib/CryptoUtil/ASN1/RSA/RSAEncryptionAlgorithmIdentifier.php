<?php

namespace CryptoUtil\ASN1\RSA;

use CryptoUtil\ASN1\AlgorithmIdentifier;
use ASN1\Type\Primitive\NullType;


class RSAEncryptionAlgorithmIdentifier extends AlgorithmIdentifier
{
	/**
	 * Constructor
	 */
	public function __construct() {
		parent::__construct(self::OID_RSA_ENCRYPTION, new NullType());
	}
}
