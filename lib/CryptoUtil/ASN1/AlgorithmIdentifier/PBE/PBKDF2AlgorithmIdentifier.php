<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\PBE;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/* @formatter:off *//*

From RFC 2898 - A.2   PBKDF2:

PBKDF2-params ::= SEQUENCE {
    salt CHOICE {
        specified OCTET STRING,
        otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
    },
    iterationCount INTEGER (1..MAX),
    keyLength INTEGER (1..MAX) OPTIONAL,
    prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
    algid-hmacWithSHA1 }

*//* @formatter:on */

/**
 * Algorithm identifier for PBKDF2 key derivation function.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-5.2
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.2
 */
class PBKDF2AlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
	/**
	 * Explicitly specified salt.
	 *
	 * @var string $_salt
	 */
	protected $_specifiedSalt;
	
	/**
	 * Iteration count.
	 *
	 * @var int $_iterationCount
	 */
	protected $_iterationCount;
	
	/**
	 * Key length.
	 *
	 * @var int|null $_keyLength
	 */
	protected $_keyLength;
	
	/**
	 * Pseudorandom function algorithm identifier.
	 *
	 * @var PRFAlgorithmIdentifier|null $_prfAlgo
	 */
	protected $_prfAlgo;
	
	/**
	 * Constructor
	 *
	 * @param string $salt
	 * @param int $iteration_count
	 * @param int|null $key_length Optional key length
	 * @param PRFAlgorithmIdentifier|null $prf_algo Default to HMAC-SHA1
	 */
	public function __construct($salt, $iteration_count, $key_length = null, 
			PRFAlgorithmIdentifier $prf_algo = null) {
		$this->_oid = self::OID_PBKDF2;
		$this->_specifiedSalt = $salt;
		$this->_iterationCount = $iteration_count;
		$this->_keyLength = $key_length;
		$this->_prfAlgo = isset($prf_algo) ? $prf_algo : new HMACWithSHA1AlgorithmIdentifier();
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters");
		}
		$el = $params->at(0);
		if (!$el->isType(Element::TYPE_OCTET_STRING)) {
			// @todo implement
			throw new \UnexpectedValueException(
				"otherSource salt not implemented");
		}
		$salt = $el->str();
		$iteration_count = $params->at(1, Element::TYPE_INTEGER)->number();
		$key_length = null;
		$prf_algo = null;
		$idx = 2;
		if ($params->has($idx, Element::TYPE_INTEGER)) {
			$key_length = $params->at($idx++)->number();
		}
		if ($params->has($idx, Element::TYPE_SEQUENCE)) {
			$prf_algo = AlgorithmIdentifier::fromASN1($params->at($idx++));
			if (!($prf_algo instanceof PRFAlgorithmIdentifier)) {
				throw new \UnexpectedValueException(
					$prf_algo->oid() .
						 " is not supported as a pseudorandom function");
			}
		}
		return new self($salt, $iteration_count, $key_length, $prf_algo);
	}
	
	/**
	 * Get salt.
	 *
	 * @return string
	 */
	public function salt() {
		return $this->_specifiedSalt;
	}
	
	/**
	 * Get iteration count.
	 *
	 * @return int
	 */
	public function iterationCount() {
		return $this->_iterationCount;
	}
	
	/**
	 * Whether key length is present.
	 *
	 * @return bool
	 */
	public function hasKeyLength() {
		return isset($this->_keyLength);
	}
	
	/**
	 * Get key length.
	 *
	 * @throws \LogicException
	 * @return int
	 */
	public function keyLength() {
		if (!$this->hasKeyLength()) {
			throw new \LogicException("Key length not specified");
		}
		return $this->_keyLength;
	}
	
	/**
	 * Get pseudorandom function algorithm.
	 *
	 * @return PRFAlgorithmIdentifier
	 */
	public function prfAlgorithmIdentifier() {
		return $this->_prfAlgo;
	}
	
	protected function _paramsASN1() {
		$elements = array();
		$elements[] = new OctetString($this->_specifiedSalt);
		$elements[] = new Integer($this->_iterationCount);
		if (isset($this->_keyLength)) {
			$elements[] = new Integer($this->_keyLength);
		}
		if ($this->_prfAlgo->oid() !== AlgorithmIdentifier::OID_HMAC_WITH_SHA1) {
			$elements[] = $this->_prfAlgo->toASN1();
		}
		return new Sequence(...$elements);
	}
}
