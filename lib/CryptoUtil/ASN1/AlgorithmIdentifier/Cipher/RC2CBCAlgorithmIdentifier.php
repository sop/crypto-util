<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier\Cipher;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\BlockCipherAlgorithmIdentifier;


/* @formatter:off *//*

Parameters may be seen in various forms. This implementation attemts
to take them all into consideration.

# RFC 2268 - A Description of the RC2(r) Encryption Algorithm
RC2-CBCParameter ::= CHOICE {
  iv IV,
  params SEQUENCE {
    version RC2Version,
    iv IV
  }
}

# RFC 2898 - PKCS #5: Password-Based Cryptography Specification Version 2.0
RC2-CBC-Parameter ::= SEQUENCE {
    rc2ParameterVersion INTEGER OPTIONAL,
    iv OCTET STRING (SIZE(8))
}

# RFC 3370 - Cryptographic Message Syntax (CMS) Algorithms
RC2CBCParameter ::= SEQUENCE {
  rc2ParameterVersion INTEGER,
  iv OCTET STRING  }  -- exactly 8 octets

*//* @formatter:on */

/**
 * Algorithm identifier for RC2 cipher in CBC mode.
 *
 * @link http://www.alvestrand.no/objectid/1.2.840.113549.3.2.html
 * @link http://www.oid-info.com/get/1.2.840.113549.3.2
 * @link https://tools.ietf.org/html/rfc2268#section-6
 * @link https://tools.ietf.org/html/rfc3370#section-5.2
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 */
class RC2CBCAlgorithmIdentifier extends CipherAlgorithmIdentifier implements 
	BlockCipherAlgorithmIdentifier
{
	/**
	 * Effective key bits.
	 *
	 * @var int $_effectiveKeyBits
	 */
	protected $_effectiveKeyBits;
	
	/**
	 * RFC 2268 translation table for effective key bits.
	 *
	 * This table maps effective key bytes from 0..255 to version number.
	 *
	 * @var array ekb => version
	 */
	const EKB_TABLE = [0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 
		0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04, 0xb6, 0xdc, 0x7d, 
		0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 
		0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 
		0x5f, 0x80, 0x36, 0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 
		0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 
		0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 
		0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 
		0x00, 0x84, 0xfa, 0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 
		0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 
		0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf, 0x3a, 
		0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 
		0x89, 0x62, 0xc6, 0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 
		0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f, 0x55, 0x51, 0xad, 
		0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 
		0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 
		0xe0, 0x01, 0xe2, 0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 
		0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 
		0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 
		0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 
		0x76, 0x5c, 0x2f, 0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 
		0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab];
	
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
			throw new \UnexpectedValueException("No parameters.");
		}
		$key_bits = 32;
		$iv = null;
		// rfc2268 a choice containing only IV
		if ($params->isType(Element::TYPE_OCTET_STRING)) {
			$iv = $params->string();
		} else {
			$params->expectType(Element::TYPE_SEQUENCE);
			$idx = 0;
			// version is optional in rfc2898
			if ($params->has($idx, Element::TYPE_INTEGER)) {
				$version = $params->at($idx++)->number();
				$key_bits = self::_versionToEKB($version);
			}
			// IV is present in all variants
			$iv = $params->at($idx, Element::TYPE_OCTET_STRING)->string();
		}
		return new self($key_bits, $iv);
	}
	
	/**
	 * Get number of effective key bits.
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
			$version = self::EKB_TABLE[$this->_effectiveKeyBits];
		}
		if (!isset($this->_initializationVector)) {
			throw new \LogicException("IV not set.");
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
	
	/**
	 * Translate version number to number of effective key bits.
	 *
	 * @param int $version
	 * @return int
	 */
	private static function _versionToEKB($version) {
		static $lut;
		if ($version > 255) {
			return $version;
		}
		if (!isset($lut)) {
			$lut = array_flip(self::EKB_TABLE);
		}
		return $lut[$version];
	}
}
