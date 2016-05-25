<?php

namespace CryptoUtil\ASN1\EC;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\PEM\PEM;


/**
 * Implements elliptic curve private key type as specified by RFC 5915.
 *
 * @link https://tools.ietf.org/html/rfc5915#section-3
 */
class ECPrivateKey extends PrivateKey
{
	/**
	 * Private key.
	 *
	 * @var string $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Named curve OID.
	 *
	 * @var string|null $_namedCurve
	 */
	protected $_namedCurve;
	
	/**
	 * ECPoint value.
	 *
	 * @var string|null $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Constructor
	 *
	 * @param string $private_key Private key
	 * @param string|null $named_curve OID of the named curve
	 * @param string|null $public_key ECPoint value
	 */
	public function __construct($private_key, $named_curve = null, 
			$public_key = null) {
		$this->_privateKey = $private_key;
		$this->_namedCurve = $named_curve;
		$this->_publicKey = $public_key;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$version = $seq->at(0, Element::TYPE_INTEGER)->number();
		if ($version != 1) {
			throw new \UnexpectedValueException("Version must be 1.");
		}
		$private_key = $seq->at(1, Element::TYPE_OCTET_STRING)->string();
		$named_curve = null;
		if ($seq->hasTagged(0)) {
			$params = $seq->getTagged(0)->explicit();
			$named_curve = $params->expectType(Element::TYPE_OBJECT_IDENTIFIER)->oid();
		}
		$public_key = null;
		if ($seq->hasTagged(1)) {
			$public_key = $seq->getTagged(1)
				->explicit(Element::TYPE_BIT_STRING)
				->string();
		}
		return new self($private_key, $named_curve, $public_key);
	}
	
	/**
	 * Initialize from DER data.
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromDER($data) {
		return self::fromASN1(Sequence::fromDER($data));
	}
	
	/**
	 *
	 * @see PrivateKey::fromPEM()
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() == PEM::TYPE_EC_PRIVATE_KEY) {
			return self::fromDER($pem->data());
		}
		if ($pem->type() != PEM::TYPE_PRIVATE_KEY) {
			throw new \UnexpectedValueException("Not a private key.");
		}
		$pki = PrivateKeyInfo::fromDER($pem->data());
		$algo = $pki->algorithmIdentifier();
		if ($algo->oid() != AlgorithmIdentifier::OID_EC_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not an elliptic curve key.");
		}
		$obj = self::fromDER($pki->privateKeyData());
		if (!isset($obj->_namedCurve)) {
			$obj->_namedCurve = $algo->namedCurve();
		}
		return $obj;
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
	 * Get self with named curve.
	 *
	 * @param string|null $named_curve Named curve OID
	 * @return self
	 */
	public function withNamedCurve($named_curve) {
		$obj = clone $this;
		$obj->_namedCurve = $named_curve;
		return $obj;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PrivateKey::privateKeyInfo()
	 * @return PrivateKeyInfo
	 */
	public function privateKeyInfo() {
		$algo = new ECPublicKeyAlgorithmIdentifier($this->namedCurve());
		// NOTE: OpenSSL strips named curve from ECPrivateKey structure
		// when serializing into PrivateKeyInfo. However RFC 5915 dictates
		// that parameters (NamedCurve) must always be included.
		return new PrivateKeyInfo($algo, $this->toDER());
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PrivateKey::publicKey()
	 * @return ECPublicKey
	 */
	public function publicKey() {
		if (!isset($this->_publicKey)) {
			throw new \LogicException("publicKey not set.");
		}
		return new ECPublicKey($this->_publicKey, $this->_namedCurve);
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array(new Integer(1), new OctetString($this->_privateKey));
		if (isset($this->_namedCurve)) {
			$elements[] = new ExplicitlyTaggedType(0, 
				new ObjectIdentifier($this->_namedCurve));
		}
		if (isset($this->_publicKey)) {
			$elements[] = new ExplicitlyTaggedType(1, 
				new BitString($this->_publicKey));
		}
		return new Sequence(...$elements);
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PrivateKey::toDER()
	 * @return string
	 */
	public function toDER() {
		return $this->toASN1()->toDER();
	}
	
	/**
	 * Get private key as a PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_EC_PRIVATE_KEY, $this->toDER());
	}
}
