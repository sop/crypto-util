<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Signature;

use ASN1\Type\Primitive\NullType;
use ASN1\Type\UnspecifiedType;


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
abstract class RFC3279RSASignatureAlgorithmIdentifier extends RSASignatureAlgorithmIdentifier
{
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters.");
		}
		$params->asNull();
		return new static();
	}
	
	protected function _paramsASN1() {
		return new NullType();
	}
}
