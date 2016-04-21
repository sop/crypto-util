<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use ASN1\Element;


/* @formatter:off *//*

From RFC 4055 - 5.  PKCS #1 Version 1.5 Signature Algorithm

   When any of these four object identifiers appears within an
   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
   MUST accept the parameters being absent as well as present.

*//* @formatter:on */

/**
 *
 * @link https://tools.ietf.org/html/rfc4055#section-5
 */
abstract class RFC4055RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
	SignatureAlgorithmIdentifier
{
	protected static function _fromASN1Params(Element $params = null) {
		return new static();
	}
	
	protected function _paramsASN1() {
		return null;
	}
}
