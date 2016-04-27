<?php

namespace CryptoUtil\ASN1;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEAlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\PBEScheme;
use CryptoUtil\PEM\PEM;


/**
 * Implements PKCS #8 <i>EncryptedPrivateKeyInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5208#section-6
 */
class EncryptedPrivateKeyInfo
{
	/**
	 * Encryption algorithm.
	 *
	 * @var PBEAlgorithmIdentifier $_algo
	 */
	protected $_algo;
	
	/**
	 * Encrypted data.
	 *
	 * @var string $_data
	 */
	protected $_data;
	
	/**
	 * Constructor
	 *
	 * @param PBEAlgorithmIdentifier $algo
	 * @param string $data Ciphertext
	 */
	protected function __construct(PBEAlgorithmIdentifier $algo, $data) {
		$this->_algo = $algo;
		$this->_data = $data;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at(0, Element::TYPE_SEQUENCE));
		if (!($algo instanceof PBEAlgorithmIdentifier)) {
			throw new \UnexpectedValueException(
				"Unsupported algorithm " . $algo->oid());
		}
		$data = $seq->at(1, Element::TYPE_OCTET_STRING)->str();
		return new self($algo, $data);
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
		if ($pem->type() != PEM::TYPE_ENCRYPTED_PRIVATE_KEY) {
			throw new \UnexpectedValueException("Invalid PEM type");
		}
		return self::fromDER($pem->data());
	}
	
	/**
	 * Get the encryption algorithm.
	 *
	 * @return PBEAlgorithmIdentifier
	 */
	public function encryptionAlgorithm() {
		return $this->_algo;
	}
	
	/**
	 * Initialize from PrivateKeyInfo.
	 *
	 * Encrypts PrivateKeyInfo with given password using given algorithm.
	 *
	 * @param PrivateKeyInfo $pki
	 * @param PBEAlgorithmIdentifier $algo
	 * @param string $password
	 * @param Crypto $crypto
	 * @return self
	 */
	public static function encryptPrivateKeyInfo(PrivateKeyInfo $pki, 
			PBEAlgorithmIdentifier $algo, $password, Crypto $crypto) {
		$data = $pki->toDER();
		$scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
		$ciphertext = $scheme->encrypt($data, $password);
		return new self($algo, $ciphertext);
	}
	
	/**
	 * Initialize from PrivateKeyInfo.
	 *
	 * Encrypts PrivateKeyInfo with given pre-derived key.
	 *
	 * @param PrivateKeyInfo $pki
	 * @param PBEAlgorithmIdentifier $algo
	 * @param string $key
	 * @param Crypto $crypto
	 * @return self
	 */
	public static function encryptPrivateKeyInfoWithDerivedKey(
			PrivateKeyInfo $pki, PBEAlgorithmIdentifier $algo, $key, 
			Crypto $crypto) {
		$data = $pki->toDER();
		$scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
		$ciphertext = $scheme->encryptWithKey($data, $key);
		return new self($algo, $ciphertext);
	}
	
	/**
	 * Decrypt PrivateKeyInfo from the encrypted data.
	 *
	 * @param string $password
	 * @param Crypto $crypto
	 * @return PrivateKeyInfo
	 */
	public function decryptPrivateKeyInfo($password, Crypto $crypto) {
		try {
			$scheme = PBEScheme::fromAlgorithmIdentifier($this->_algo, $crypto);
			$data = $scheme->decrypt($this->_data, $password);
			return PrivateKeyInfo::fromASN1(Sequence::fromDER($data));
		} catch (\RuntimeException $e) {
			throw new \RuntimeException("Failed to decrypt private key", 0, $e);
		}
	}
	
	/**
	 * Get ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_algo->toASN1(), 
			new OctetString($this->_data));
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
	 * Get encrypted private key PEM.
	 *
	 * @return PEM
	 */
	public function PEM() {
		return new PEM(PEM::TYPE_ENCRYPTED_PRIVATE_KEY, $this->toASN1()->toDER());
	}
}
