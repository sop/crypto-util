<?php

namespace CryptoUtil\ASN1\AlgorithmIdentifier;

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Generic algorithm identifier to hold parameters as ASN.1 objects.
 */
class GenericAlgorithmIdentifier extends AlgorithmIdentifier
{
	/**
	 * Parameters.
	 *
	 * @var Element|null $_params
	 */
	protected $_params;
	
	/**
	 * Constructor
	 *
	 * @param string $oid Algorithm OID
	 * @param UnspecifiedType|null $params Parameters
	 */
	public function __construct($oid, UnspecifiedType $params = null) {
		$this->_oid = $oid;
		$this->_params = $params ? $params->asElement() : null;
	}
	
	/**
	 *
	 * @see \CryptoUtil\ASN1\AlgorithmIdentifier::_paramsASN1()
	 * @return Element|null
	 */
	protected function _paramsASN1() {
		return $this->_params;
	}
}
