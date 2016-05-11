<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Crypto;

use ASN1\Element;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 5480 - 2.1.1.  Unrestricted Algorithm Identifier and Parameters:

The parameter for id-ecPublicKey is as follows and MUST always be
present:

  ECParameters ::= CHOICE {
    namedCurve         OBJECT IDENTIFIER
    -- implicitCurve   NULL
    -- specifiedCurve  SpecifiedECDomain
  }

*//* @formatter:on */

/**
 * Algorithm identifier for the elliptic curve public key.
 *
 * @link https://tools.ietf.org/html/rfc5480#section-2.1.1
 */
class ECPublicKeyAlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
	/**
	 * prime192v1/secp192r1 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.1
	 * @var string
	 */
	const CURVE_PRIME192V1 = "1.2.840.10045.3.1.1";
	
	/**
	 * prime192v2 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.2
	 * @var string
	 */
	const CURVE_PRIME192V2 = "1.2.840.10045.3.1.2";
	
	/**
	 * prime192v3 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.3
	 * @var string
	 */
	const CURVE_PRIME192V3 = "1.2.840.10045.3.1.3";
	
	/**
	 * prime239v1 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.4
	 * @var string
	 */
	const CURVE_PRIME239V1 = "1.2.840.10045.3.1.4";
	
	/**
	 * prime239v2 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.5
	 * @var string
	 */
	const CURVE_PRIME239V2 = "1.2.840.10045.3.1.5";
	
	/**
	 * prime239v3 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.6
	 * @var string
	 */
	const CURVE_PRIME239V3 = "1.2.840.10045.3.1.6";
	
	/**
	 * prime256v1/secp256r1 curve OID.
	 *
	 * @link http://oid-info.com/get/1.2.840.10045.3.1.7
	 * @var string
	 */
	const CURVE_PRIME256V1 = "1.2.840.10045.3.1.7";
	
	/**
	 * OID of the named curve.
	 *
	 * @var string $_namedCurve
	 */
	protected $_namedCurve;
	
	/**
	 * Constructor
	 *
	 * @param string OID Curve identifier
	 */
	public function __construct($named_curve) {
		$this->_oid = self::OID_EC_PUBLIC_KEY;
		$this->_namedCurve = $named_curve;
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters.");
		}
		$named_curve = $params->expectType(Element::TYPE_OBJECT_IDENTIFIER)->oid();
		return new self($named_curve);
	}
	
	/**
	 * Get OID of the named curve.
	 *
	 * @return string
	 */
	public function namedCurve() {
		return $this->_namedCurve;
	}
	
	protected function _paramsASN1() {
		return new ObjectIdentifier($this->_namedCurve);
	}
}
