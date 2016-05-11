<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndDESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class PBES1AITest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidSalt() {
		new PBEWithMD5AndDESCBCAlgorithmIdentifier("1234", 1);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testNoParamsFail() {
		$ai = new PBEWithMD5AndDESCBCAlgorithmIdentifier("12345678", 1);
		$seq = $ai->toASN1()->withoutElement(1);
		AlgorithmIdentifier::fromASN1($seq);
	}
}
