<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\RFC4231HMACAlgorithmIdentifier;
use CryptoUtil\PBE\PRF\HMACSHA1;
use CryptoUtil\PBE\PRF\PRF;


/**
 * @group pbe
 * @group prf
 */
class PRFTest extends PHPUnit_Framework_TestCase
{
	public function testInvoke() {
		$prf = new HMACSHA1();
		$result = $prf("arg1", "arg2");
		$this->assertEquals($prf->length(), strlen($result));
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedAlgo() {
		$algo = new PRFTest_UnsupportedAlgo();
		PRF::fromAlgorithmIdentifier($algo);
	}
}


class PRFTest_UnsupportedAlgo extends RFC4231HMACAlgorithmIdentifier
{
	public function __construct() {
		$this->_oid = "1.3.6.1.3";
	}
	
	public function name() {
		return "";
	}
}
