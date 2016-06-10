<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;

use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Base class for signature algorithms employing RSASSA.
 */
abstract class RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	SignatureAlgorithmIdentifier
{
	public function supportsKeyAlgorithm(AlgorithmIdentifier $algo) {
		return $algo->oid() == self::OID_RSA_ENCRYPTION;
	}
}
