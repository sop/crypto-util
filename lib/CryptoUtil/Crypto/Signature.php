<?php

namespace CryptoUtil\Crypto;

use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\StringType;


/**
 * Class to represent digital signature value.
 */
class Signature
{
	/**
	 * Signature value in octets.
	 *
	 * @var string $_octets
	 */
	protected $_octets;
	
	/**
	 * Constructor
	 *
	 * @param string $octets Signature value in octets
	 */
	public function __construct($octets) {
		$this->_octets = $octets;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param StringType $el Any string based ASN.1 element
	 * @return self
	 */
	public static function fromASN1(StringType $el) {
		return new self($el->str());
	}
	
	/**
	 * Get signature octets.
	 *
	 * @return string
	 */
	public function octets() {
		return $this->_octets;
	}
	
	/**
	 * Get signature as an ASN.1 octet string.
	 *
	 * @return OctetString
	 */
	public function toOctetString() {
		return new OctetString($this->_octets);
	}
	
	/**
	 * Get signature as an ASN.1 bit string.
	 *
	 * Number of unused bits shall always be 0.
	 *
	 * @return BitString
	 */
	public function toBitString() {
		return new BitString($this->_octets);
	}
}
