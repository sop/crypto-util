<?php

namespace CryptoUtil\ASN1;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;


/**
 * Implements PKCS #8 PrivateKeyInfo ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5208#section-5
 */
class PrivateKeyInfo
{
	/**
	 * Algorithm
	 *
	 * @var AlgorithmIdentifier $_algo
	 */
	protected $_algo;
	
	/**
	 * Private key data
	 *
	 * @var string $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Constructor
	 *
	 * @param AlgorithmIdentifier $algo Algorithm
	 * @param string $key Private key data
	 */
	public function __construct(AlgorithmIdentifier $algo, $key) {
		$this->_algo = $algo;
		$this->_privateKey = $key;
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
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at(1, Element::TYPE_SEQUENCE));
		$key = $seq->at(2, Element::TYPE_STRING)->str();
		return new self($algo, $key);
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
	 * Get algorithm
	 *
	 * @return AlgorithmIdentifier
	 */
	public function algorithmIdentifier() {
		return $this->_algo;
	}
	
	/**
	 * Get private key data
	 *
	 * @return string
	 */
	public function privateKeyData() {
		return $this->_privateKey;
	}
}
