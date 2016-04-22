<?php

namespace CryptoUtil\ASN1\RSA;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\PEM\PEM;


/**
 * Implements PKCS #1 RSAPrivateKey ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2437#section-11.1.2
 */
class RSAPrivateKey extends PrivateKey
{
	/**
	 * Modulus
	 *
	 * @var int|string $_modulus
	 */
	protected $_modulus;
	
	/**
	 * Public exponent
	 *
	 * @var int|string $_publicExponent
	 */
	protected $_publicExponent;
	
	/**
	 * Private exponent
	 *
	 * @var int|string $_privateExponent
	 */
	protected $_privateExponent;
	
	/**
	 * First prime factor
	 *
	 * @var int|string $_prime1
	 */
	protected $_prime1;
	
	/**
	 * Second prime factor
	 *
	 * @var int|string $_prime2
	 */
	protected $_prime2;
	
	/**
	 * First factor exponent
	 *
	 * @var int|string $_exponent1
	 */
	protected $_exponent1;
	
	/**
	 * Second factor exponent
	 *
	 * @var int|string $_exponent2
	 */
	protected $_exponent2;
	
	/**
	 * CRT coefficient of the second factor
	 *
	 * @var int|string $_coefficient
	 */
	protected $_coefficient;
	
	/**
	 * Constructor
	 *
	 * @param int|string $n Modulus
	 * @param int|string $e Public exponent
	 * @param int|string $d Private exponent
	 * @param int|string $p First prime factor
	 * @param int|string $q Second prime factor
	 * @param int|string $dp First factor exponent
	 * @param int|string $dq Second factor exponent
	 * @param int|string $qi CRT coefficient of the second factor
	 */
	public function __construct($n, $e, $d, $p, $q, $dp, $dq, $qi) {
		$this->_modulus = $n;
		$this->_publicExponent = $e;
		$this->_privateExponent = $d;
		$this->_prime1 = $p;
		$this->_prime2 = $q;
		$this->_exponent1 = $dp;
		$this->_exponent2 = $dq;
		$this->_coefficient = $qi;
	}
	
	/**
	 * Initialize from ASN.1
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$version = $seq->at(0, Element::TYPE_INTEGER)->number();
		if ($version != 0) {
			throw new \UnexpectedValueException("Version must be 0");
		}
		$n = $seq->at(1, Element::TYPE_INTEGER)->number();
		$e = $seq->at(2, Element::TYPE_INTEGER)->number();
		$d = $seq->at(3, Element::TYPE_INTEGER)->number();
		$p = $seq->at(4, Element::TYPE_INTEGER)->number();
		$q = $seq->at(5, Element::TYPE_INTEGER)->number();
		$dp = $seq->at(6, Element::TYPE_INTEGER)->number();
		$dq = $seq->at(7, Element::TYPE_INTEGER)->number();
		$qi = $seq->at(8, Element::TYPE_INTEGER)->number();
		return new self($n, $e, $d, $p, $q, $dp, $dq, $qi);
	}
	
	/**
	 * Initialize from DER data
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromDER($data) {
		return self::fromASN1(Sequence::fromDER($data));
	}
	
	/**
	 * Initialize from PEM
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		if ($pem->type() == PEM::TYPE_RSA_PRIVATE_KEY) {
			return self::fromDER($pem->data());
		}
		if ($pem->type() != PEM::TYPE_PRIVATE_KEY) {
			throw new \UnexpectedValueException("Invalid PEM type");
		}
		$pki = PrivateKeyInfo::fromDER($pem->data());
		if ($pki->algorithmIdentifier()->oid() !=
			 AlgorithmIdentifier::OID_RSA_ENCRYPTION) {
			throw new \UnexpectedValueException("Not an RSA private key");
		}
		return self::fromDER($pki->privateKeyData());
	}
	
	/**
	 * Get modulus
	 *
	 * @return int|string
	 */
	public function modulus() {
		return $this->_modulus;
	}
	
	/**
	 * Get public exponent
	 *
	 * @return int|string
	 */
	public function publicExponent() {
		return $this->_publicExponent;
	}
	
	/**
	 * Get private exponent
	 *
	 * @return int|string
	 */
	public function privateExponent() {
		return $this->_privateExponent;
	}
	
	/**
	 * Get first prime factor
	 *
	 * @return int|string
	 */
	public function prime1() {
		return $this->_prime1;
	}
	
	/**
	 * Get second prime factor
	 *
	 * @return int|string
	 */
	public function prime2() {
		return $this->_prime2;
	}
	
	/**
	 * Get first factor exponent
	 *
	 * @return int|string
	 */
	public function exponent1() {
		return $this->_exponent1;
	}
	
	/**
	 * Get second factor exponent
	 *
	 * @return int|string
	 */
	public function exponent2() {
		return $this->_exponent2;
	}
	
	/**
	 * Get CRT coefficient of the second factor
	 *
	 * @return int|string
	 */
	public function coefficient() {
		return $this->_coefficient;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PrivateKey::privateKeyInfo()
	 * @return PrivateKeyInfo
	 */
	public function privateKeyInfo() {
		return new PrivateKeyInfo(new RSAEncryptionAlgorithmIdentifier(), 
			$this->toDER());
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\PrivateKey::publicKey()
	 * @return RSAPublicKey
	 */
	public function publicKey() {
		return new RSAPublicKey($this->_modulus, $this->_publicExponent);
	}
	
	/**
	 * Generate ASN.1 structure
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence(new Integer(0), new Integer($this->_modulus), 
			new Integer($this->_publicExponent), 
			new Integer($this->_privateExponent), new Integer($this->_prime1), 
			new Integer($this->_prime2), new Integer($this->_exponent1), 
			new Integer($this->_exponent2), new Integer($this->_coefficient));
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
	 * Generate PEM
	 *
	 * @return PEM
	 */
	public function toPEM() {
		return new PEM(PEM::TYPE_RSA_PRIVATE_KEY, $this->toDER());
	}
}
