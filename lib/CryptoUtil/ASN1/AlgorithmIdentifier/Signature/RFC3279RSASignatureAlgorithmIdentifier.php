<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;

use ASN1\Type\Primitive\NullType;
use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 3279 - 2.2.1  RSA Signature Algorithm:

   When any of these three OIDs appears within the ASN.1 type
   AlgorithmIdentifier, the parameters component of that type SHALL be
   the ASN.1 type NULL.

*//* @formatter:on */

/**
 *
 * @link https://tools.ietf.org/html/rfc3279#section-2.2.1
 */
abstract class RFC3279RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	SignatureAlgorithmIdentifier
{
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		$params->asNull();
		return new static();
	}
	
	protected function _paramsASN1() {
		return new NullType();
	}
}
