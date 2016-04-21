<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Primitive\NullType;


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
abstract class RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	SignatureAlgorithmIdentifier
{
	protected static function _fromASN1Params(Element $params = null) {
		return new static();
	}
	
	protected function _paramsASN1() {
		return new NullType();
	}
}
