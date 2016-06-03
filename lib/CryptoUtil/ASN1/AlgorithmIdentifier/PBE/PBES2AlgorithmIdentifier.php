<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 2898 - A.4 PBES2:

The parameters field associated with this OID in an
AlgorithmIdentifier shall have type PBES2-params:

PBES2-params ::= SEQUENCE {
    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

*//* @formatter:on */

/**
 * Algorithm identifier for PBES2 encryption scheme.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6.2
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.4
 */
class PBES2AlgorithmIdentifier extends PBEAlgorithmIdentifier
{
	/**
	 * PBKDF2 algorithm identifier.
	 *
	 * @var PBKDF2AlgorithmIdentifier $_kdf
	 */
	protected $_kdf;
	
	/**
	 * Encryption algorithm identifier.
	 *
	 * @var BlockCipherAlgorithmIdentifier $_es
	 */
	protected $_es;
	
	/**
	 * Constructor
	 *
	 * @param PBKDF2AlgorithmIdentifier $kdf
	 * @param BlockCipherAlgorithmIdentifier $es
	 */
	public function __construct(PBKDF2AlgorithmIdentifier $kdf, 
			BlockCipherAlgorithmIdentifier $es) {
		parent::__construct($kdf->salt(), $kdf->iterationCount());
		$this->_oid = self::OID_PBES2;
		$this->_kdf = $kdf;
		$this->_es = $es;
	}
	
	protected static function _fromASN1Params(UnspecifiedType $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters.");
		}
		$seq = $params->asSequence();
		$kdf = AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
		// ensure we got proper key derivation function algorithm
		if (!($kdf instanceof PBKDF2AlgorithmIdentifier)) {
			throw new \UnexpectedValueException(
				"KDF algorithm " . $kdf->oid() . " not supported.");
		}
		$es = AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence());
		// ensure we got proper encryption algorithm
		if (!($es instanceof BlockCipherAlgorithmIdentifier)) {
			throw new \UnexpectedValueException(
				"ES algorithm " . $es->oid() . " not supported.");
		}
		return new self($kdf, $es);
	}
	
	/**
	 * Get key derivation function algorithm identifier.
	 *
	 * @return PBKDF2AlgorithmIdentifier
	 */
	public function kdfAlgorithmIdentifier() {
		return $this->_kdf;
	}
	
	/**
	 * Get encryption scheme algorithm identifier.
	 *
	 * @return BlockCipherAlgorithmIdentifier
	 */
	public function esAlgorithmIdentifier() {
		return $this->_es;
	}
	
	protected function _paramsASN1() {
		return new Sequence($this->_kdf->toASN1(), $this->_es->toASN1());
	}
}
