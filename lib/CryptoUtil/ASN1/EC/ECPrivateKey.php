<?php

namespace CryptoUtil\ASN1\EC;

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;


/**
 * Implements elliptic curve private key type as specified by RFC 5915.
 *
 * @link https://tools.ietf.org/html/rfc5915#section-3
 */
class ECPrivateKey extends PrivateKey
{
	/**
	 * Private key
	 *
	 * @var string $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Named curve OID
	 *
	 * @var string|null $_namedCurve
	 */
	protected $_namedCurve;
	
	/**
	 * ECPoint value
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
			throw new \UnexpectedValueException("Invalid version");
		}
		$private_key = $seq->at(1, Element::TYPE_OCTET_STRING)->str();
		$named_curve = null;
		if ($seq->hasTagged(0)) {
			$params = $seq->getTagged(0)->explicit();
			$named_curve = $params->expectType(Element::TYPE_OBJECT_IDENTIFIER)->oid();
		}
		$public_key = null;
		if ($seq->hasTagged(1)) {
			$public_key = $seq->getTagged(1)
				->explicit(Element::TYPE_BIT_STRING)
				->str();
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
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() == PEM::TYPE_EC_PRIVATE_KEY) {
			return self::fromDER($pem->data());
		}
		if ($pem->type() != PEM::TYPE_PRIVATE_KEY) {
			throw new \UnexpectedValueException("Not a private key");
		}
		$pki = PrivateKeyInfo::fromDER($pem->data());
		if ($pki->algorithmIdentifier()->oid() !=
			 AlgorithmIdentifier::OID_EC_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Not an elliptic curve key");
		}
		return self::fromDER($pki->privateKeyData());
	}
	
	public function publicKey() {
		if (!isset($this->_publicKey)) {
			throw new \LogicException("No public key");
		}
		return new ECPublicKey($this->_publicKey);
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
