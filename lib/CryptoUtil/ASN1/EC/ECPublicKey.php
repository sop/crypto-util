<?php

namespace CryptoUtil\ASN1\EC;

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use ASN1\Type\Primitive\OctetString;


/**
 * Implements elliptic curve public key type as specified by RFC 5480.
 *
 * @link https://tools.ietf.org/html/rfc5480#section-2.2
 */
class ECPublicKey extends PublicKey
{
	/**
	 * Elliptic curve public key
	 *
	 * @var string
	 */
	protected $_ecPoint;
	
	/**
	 * Constructor
	 *
	 * @param string $ec_point
	 */
	public function __construct($ec_point) {
		$this->_ecPoint = $ec_point;
	}
	
	public static function fromPEM(PEM $pem) {
		if ($pem->type() != PEM::TYPE_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not a public key");
		}
		$pki = PublicKeyInfo::fromDER($pem->data());
		if ($pki->algorithmIdentifier()->oid() !=
			 AlgorithmIdentifier::OID_EC_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not an elliptic curve key");
		}
		// ECPoint is directly mapped into public key data
		return new self($pki->publicKeyData());
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
