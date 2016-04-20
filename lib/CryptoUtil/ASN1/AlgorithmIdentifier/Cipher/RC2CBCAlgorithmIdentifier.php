<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\BlockCipherAlgorithmIdentifier;
use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;


/**
 *
 * @link http://www.alvestrand.no/objectid/1.2.840.113549.3.2.html
 * @link http://www.oid-info.com/get/1.2.840.113549.3.2
 * @link https://tools.ietf.org/html/rfc2268#section-6
 * @link https://tools.ietf.org/html/rfc3370#section-5.2
 */
class RC2CBCAlgorithmIdentifier extends CipherAlgorithmIdentifier implements 
	BlockCipherAlgorithmIdentifier
{
	/**
	 * Effective key bits
	 *
	 * @var int $_effectiveKeyBits
	 */
	protected $_effectiveKeyBits;
	
	/**
	 *
	 * @todo Implement the complete translation table as defined in
	 *       https://tools.ietf.org/html/rfc2268#section-6
	 * @var array
	 */
	private static $_versionToKeySize = array(160 => 40, 120 => 64, 58 => 128);
	
	/**
	 * Constructor
	 *
	 * @param int $key_bits
	 * @param string|null $iv
	 */
	public function __construct($key_bits = 64, $iv = null) {
		$this->_oid = self::OID_RC2_CBC;
		$this->_effectiveKeyBits = $key_bits;
		$this->_initializationVector = $iv;
	}
	
	protected static function _fromASN1Params(Element $params = null) {
		if (!isset($params)) {
			throw new \UnexpectedValueException("No parameters");
		}
		$key_bits = 32;
		$iv = null;
		// rfc2268 allows choice of only IV
		if ($params->isType(Element::TYPE_OCTET_STRING)) {
			$iv = $params->str();
		} else {
			$params->expectType(Element::TYPE_SEQUENCE);
			$idx = 0;
			if ($params->has($idx, Element::TYPE_INTEGER)) {
				$version = $params->at($idx++)->number();
				if ($version >= 256) {
					$key_bits = $version;
				} else {
					if (!isset(self::$_versionToKeySize[$version])) {
						throw new \UnexpectedValueException(
							"Unsupported version");
					}
					$key_bits = self::$_versionToKeySize[$version];
				}
			}
			$iv = $params->at($idx, Element::TYPE_OCTET_STRING)->str();
		}
		return new self($key_bits, $iv);
	}
	
	/**
	 * Get number of effective key bits
	 *
	 * @return int
	 */
	public function effectiveKeyBits() {
		return $this->_effectiveKeyBits;
	}
	
	protected function _paramsASN1() {
		if ($this->_effectiveKeyBits >= 256) {
			$version = $this->_effectiveKeyBits;
		} else {
			$lut = array_flip(self::$_versionToKeySize);
			if (!isset($lut[$this->_effectiveKeyBits])) {
				throw new \UnexpectedValueException("Unsupported key size");
			}
			$version = $lut[$this->_effectiveKeyBits];
		}
		if (!isset($this->_initializationVector)) {
			throw new \UnexpectedValueException("IV not set");
		}
		return new Sequence(new Integer($version), 
			new OctetString($this->_initializationVector));
	}
	
	public function blockSize() {
		return 8;
	}
	
	public function keySize() {
		return (int) round($this->_effectiveKeyBits / 8);
	}
}
