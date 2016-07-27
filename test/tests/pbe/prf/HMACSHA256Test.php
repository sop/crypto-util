<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use CryptoUtil\PBE\PRF\HMACSHA256;
use CryptoUtil\PBE\PRF\PRF;


/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA256Test extends PHPUnit_Framework_TestCase
{
	public function testCreateFromAlgo() {
		$algo = new HMACWithSHA256AlgorithmIdentifier();
		$prf = PRF::fromAlgorithmIdentifier($algo);
		$this->assertInstanceOf(HMACSHA256::class, $prf);
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
