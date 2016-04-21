<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Crypto;

use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Primitive\ObjectIdentifier;


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
	 * OID of the named curve
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
			throw new \UnexpectedValueException("No parameters");
		}
		$named_curve = $params->expectType(Element::TYPE_OBJECT_IDENTIFIER)->oid();
		return new self($named_curve);
	}
	
	/**
	 * Get OID of the named curve
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
