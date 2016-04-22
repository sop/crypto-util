<?php

namespace CryptoUtil\ASN1\EC;

use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\PEM\PEM;


/**
 * Implements elliptic curve public key type as specified by RFC 5480.
 *
 * @link https://tools.ietf.org/html/rfc5480#section-2.2
 */
class ECPublicKey extends PublicKey
{
	/**
	 * Elliptic curve public key.
	 *
	 * @var string
	 */
	protected $_ecPoint;
	
	/**
	 * Named curve OID.
	 *
	 * Named curve is not a part of ECPublicKey, but it's stored as a hint
	 * for the purpose of PublicKeyInfo generation.
	 *
	 * @var string|null $_namedCurve
	 */
	protected $_namedCurve;
	
	/**
	 * Constructor
	 *
	 * @param string $ec_point ECPoint
	 * @param string|null $named_curve Named curve OID
	 */
	public function __construct($ec_point, $named_curve = null) {
		$this->_ecPoint = $ec_point;
		$this->_namedCurve = $named_curve;
	}
	
	public static function fromPEM(PEM $pem) {
		if ($pem->type() != PEM::TYPE_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not a public key");
		}
		$pki = PublicKeyInfo::fromDER($pem->data());
		$algo = $pki->algorithmIdentifier();
		if ($algo->oid() != AlgorithmIdentifier::OID_EC_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not an elliptic curve key");
		}
		// ECPoint is directly mapped into public key data
		return new self($pki->publicKeyData(), $algo->namedCurve());
	}
	
	/**
	 * Get ECPoint value
	 *
	 * @return string
	 */
	public function ECPoint() {
		return $this->_ecPoint;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PublicKey::publicKeyInfo()
	 * @return PublicKeyInfo
	 */
	public function publicKeyInfo() {
		if (!isset($this->_namedCurve)) {
			throw new \LogicException("No named curve");
		}
		$algo = new ECPublicKeyAlgorithmIdentifier($this->_namedCurve);
		return new PublicKeyInfo($algo, $this->_ecPoint);
	}
	
	/**
	 * Generate ASN.1 element.
	 *
	 * @return OctetString
	 */
	public function toASN1() {
		return new OctetString($this->_ecPoint);
	}
	
	public function toDER() {
		return $this->toASN1()->toDER();
	}
}
