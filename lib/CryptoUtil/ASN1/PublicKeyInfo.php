<?php

namespace CryptoUtil\ASN1;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\ASN1\RSA\RSAPublicKey;
use CryptoUtil\PEM\PEM;


/**
 * Implements X.509 SubjectPublicKeyInfo ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1
 */
class PublicKeyInfo
{
	/**
	 * Algorithm identifier.
	 *
	 * @var AlgorithmIdentifier $_algo
	 */
	protected $_algo;
	
	/**
	 * Public key data.
	 *
	 * @var string $_publicKeyData
	 */
	protected $_publicKeyData;
	
	/**
	 * Constructor
	 *
	 * @param AlgorithmIdentifier $algo Algorithm
	 * @param string $key Public key data
	 */
	public function __construct(AlgorithmIdentifier $algo, $key) {
		$this->_algo = $algo;
		$this->_publicKeyData = $key;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$algo = AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
		$key = $seq->at(1)
			->asBitString()
			->string();
		return new self($algo, $key);
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() != PEM::TYPE_PUBLIC_KEY) {
			throw new \UnexpectedValueException("Invalid PEM type.");
		}
		return self::fromDER($pem->data());
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
	 * Get algorithm identifier.
	 *
	 * @return AlgorithmIdentifier
	 */
	public function algorithmIdentifier() {
		return $this->_algo;
	}
	
	/**
	 * Get public key data.
	 *
	 * @return string
	 */
	public function publicKeyData() {
		return $this->_publicKeyData;
	}
	
	/**
	 * Get public key.
	 *
	 * @throws \RuntimeException
	 * @return PublicKey
	 */
	public function publicKey() {
		$algo = $this->algorithmIdentifier();
		switch ($algo->oid()) {
		// RSA
		case AlgorithmIdentifier::OID_RSA_ENCRYPTION:
			return RSAPublicKey::fromDER($this->_publicKeyData);
		// elliptic curve
		case AlgorithmIdentifier::OID_EC_PUBLIC_KEY:
			if (!$algo instanceof ECPublicKeyAlgorithmIdentifier) {
				throw new \UnexpectedValueException("Not an EC algorithm.");
			}
			// ECPoint is directly mapped into public key data
			return new ECPublicKey($this->_publicKeyData, $algo->namedCurve());
		}
		throw new \RuntimeException(
			"Public key " . $algo->oid() . " not supported.");
	}
	
	/**
	 * Get key identifier using method 1 as described by RFC 5280.
	 *
	 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.2
	 * @return string 20 bytes (160 bits) long identifier
	 */
	public function keyIdentifier() {
		return sha1($this->_publicKeyData, true);
	}
	
	/**
	 * Get key identifier using method 2 as described by RFC 5280.
	 *
	 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.2
	 * @return string 8 bytes (64 bits) long identifier
	 */
	public function keyIdentifier64() {
		$id = substr($this->keyIdentifier(), -8);
		$c = (ord($id[0]) & 0x0f) | 0x40;
		$id[0] = chr($c);
		return $id;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_algo->toASN1(), 
			new BitString($this->_publicKeyData));
	}
	
	/**
	 * Generate DER encoding.
	 *
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
		return new PEM(PEM::TYPE_PUBLIC_KEY, $this->toDER());
	}
}
