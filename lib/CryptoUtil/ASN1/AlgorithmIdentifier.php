<?php

namespace CryptoUtil\ASN1;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;


/**
 * Implements PKCS #5 AlgorithmIdentifier ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 */
class AlgorithmIdentifier
{
	const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
	
	/**
	 * Object identifier
	 *
	 * @var string $_oid
	 */
	protected $_oid;
	
	/**
	 * Algorithm specific parameters
	 *
	 * @var Element|null $_params
	 */
	protected $_params;
	
	/**
	 * Constructor
	 *
	 * @param string $oid Algorithm OID
	 * @param Element $params Parameters
	 */
	public function __construct($oid, Element $params = null) {
		$this->_oid = $oid;
		$this->_params = $params;
	}
	
	/**
	 * Initialize from ASN.1
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$oid = $seq->at(0, Element::TYPE_OBJECT_IDENTIFIER)->oid();
		$params = $seq->has(1) ? $seq->at(1) : null;
		return new self($oid, $params);
	}
	
	/**
	 * Get algorithm OID
	 *
	 * @return string
	 */
	public function oid() {
		return $this->_oid;
	}
}
