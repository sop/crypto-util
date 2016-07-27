<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA512AlgorithmIdentifier;
use CryptoUtil\PBE\PRF\HMACSHA512;
use CryptoUtil\PBE\PRF\PRF;


/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA512Test extends PHPUnit_Framework_TestCase
{
	public function testCreateFromAlgo() {
		$algo = new HMACWithSHA512AlgorithmIdentifier();
		$prf = PRF::fromAlgorithmIdentifier($algo);
		$this->assertInstanceOf(HMACSHA512::class, $prf);
		return $prf;
	}
	
	/**
	 * @depends testCreateFromAlgo
	 *
	 * @param PRF $prf
	 */
	public function testInvoke(PRF $prf) {
		$hash = $prf("a1", "a2");
		$this->assertEquals($prf->length(), strlen($hash));
	}
}
