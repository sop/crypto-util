<?php

namespace CryptoUtil\ASN1\EC;

use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Conversion\ECConversion;
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
		// first octet must be 0x04 for uncompressed form, and 0x02 or 0x03
		// for compressed form.
		if (!strlen($ec_point) || !in_array(ord($ec_point[0]), [2, 3, 4])) {
			throw new \InvalidArgumentException("Invalid ECPoint.");
		}
		$this->_ecPoint = $ec_point;
		$this->_namedCurve = $named_curve;
	}
	
	/**
	 * Initialize from curve point coordinates.
	 *
	 * @param int|string $x X coordinate as a base10 number
	 * @param int|string $y Y coordinate as a base10 number
	 * @param string|null $named_curve Named curve OID
	 * @return self
	 */
	public static function fromCoordinates($x, $y, $named_curve = null) {
		$x_os = ECConversion::integerToOctetString(new Integer($x))->string();
		$y_os = ECConversion::integerToOctetString(new Integer($y))->string();
		$ec_point = "\x4$x_os$y_os";
		return new self($ec_point, $named_curve);
	}
	
	/**
	 *
	 * @see PublicKey::fromPEM()
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() != PEM::TYPE_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not a public key.");
		}
		$pki = PublicKeyInfo::fromDER($pem->data());
		$algo = $pki->algorithmIdentifier();
		if ($algo->oid() != AlgorithmIdentifier::OID_EC_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not an elliptic curve key.");
		}
		// ECPoint is directly mapped into public key data
		return new self($pki->publicKeyData(), $algo->namedCurve());
	}
	
	/**
	 * Get ECPoint value.
	 *
	 * @return string
	 */
	public function ECPoint() {
		return $this->_ecPoint;
	}
	
	/**
	 * Get curve point coordinates.
	 *
	 * @return Integer[] Tuple of X and Y coordinates as ASN.1 integer.
	 */
	public function curvePoint() {
		list($x, $y) = $this->_splitECPoint();
		return [ECConversion::octetStringToInteger(new OctetString($x)), 
			ECConversion::octetStringToInteger(new OctetString($y))];
	}
	
	/**
	 * Split ECPoint to X and Y field elements.
	 *
	 * @throws \RuntimeException
	 * @return string[] Tuple of X and Y field elements as a string.
	 */
	private function _splitECPoint() {
		if ($this->isCompressed()) {
			throw new \RuntimeException("EC point compression not supported.");
		}
		$str = substr($this->_ecPoint, 1);
		list($x, $y) = str_split($str, floor(strlen($str) / 2));
		return [$x, $y];
	}
	
	/**
	 * Whether ECPoint is in compressed form.
	 *
	 * @return bool
	 */
	public function isCompressed() {
		$c = ord($this->_ecPoint[0]);
		return $c != 4;
	}
	
	/**
	 * Whether named curve is present.
	 *
	 * @return bool
	 */
	public function hasNamedCurve() {
		return isset($this->_namedCurve);
	}
	
	/**
	 * Get named curve OID.
	 *
	 * @throws \LogicException
	 * @return string
	 */
	public function namedCurve() {
		if (!$this->hasNamedCurve()) {
			throw new \LogicException("namedCurve not set.");
		}
		return $this->_namedCurve;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PublicKey::publicKeyInfo()
	 * @return PublicKeyInfo
	 */
	public function publicKeyInfo() {
		if (!isset($this->_namedCurve)) {
			throw new \LogicException("namedCurve not set.");
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
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PublicKey::toDER()
	 * @return string
	 */
	public function toDER() {
		return $this->toASN1()->toDER();
	}
}
