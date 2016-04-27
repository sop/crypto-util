<?php

namespace CryptoUtil\ASN1\RSA;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\PEM\PEM;


/**
 * Implements PKCS #1 RSAPublicKey ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2437#section-11.1.1
 */
class RSAPublicKey extends PublicKey
{
	/**
	 * Modulus.
	 *
	 * @var int|string $_modulus
	 */
	protected $_modulus;
	
	/**
	 * Public exponent.
	 *
	 * @var int|string $_publicExponent
	 */
	protected $_publicExponent;
	
	/**
	 * Constructor
	 *
	 * @param int|string $n Modulus
	 * @param int|string $e Public exponent
	 */
	public function __construct($n, $e) {
		$this->_modulus = $n;
		$this->_publicExponent = $e;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$n = $seq->at(0, Element::TYPE_INTEGER)->number();
		$e = $seq->at(1, Element::TYPE_INTEGER)->number();
		return new self($n, $e);
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
	 * @see PublicKey::fromPEM()
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() == PEM::TYPE_RSA_PUBLIC_KEY) {
			return self::fromDER($pem->data());
		}
		if ($pem->type() != PEM::TYPE_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Invalid PEM type");
		}
		$pki = PublicKeyInfo::fromDER($pem->data());
		if ($pki->algorithmIdentifier()->oid() !=
			 AlgorithmIdentifier::OID_RSA_ENCRYPTION) {
			throw new \UnexpectedValueException("Not an RSA public key");
		}
		return self::fromDER($pki->publicKeyData());
	}
	
	/**
	 * Get modulus.
	 *
	 * @return int|string
	 */
	public function modulus() {
		return $this->_modulus;
	}
	
	/**
	 * Get public exponent.
	 *
	 * @return int|string
	 */
	public function publicExponent() {
		return $this->_publicExponent;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PublicKey::publicKeyInfo()
	 * @return PublicKeyInfo
	 */
	public function publicKeyInfo() {
		return new PublicKeyInfo(new RSAEncryptionAlgorithmIdentifier(), 
			$this->toDER());
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence(new Integer($this->_modulus), 
			new Integer($this->_publicExponent));
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PublicKey::toDER()
	 * @return string
	 */
	public function toDER() {
		return $this->toASN1()->toDER();
	}
	
	/**
	 * Generate PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_RSA_PUBLIC_KEY, $this->toDER());
	}
}
