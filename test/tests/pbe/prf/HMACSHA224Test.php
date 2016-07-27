<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA224AlgorithmIdentifier;
use CryptoUtil\PBE\PRF\HMACSHA224;
use CryptoUtil\PBE\PRF\PRF;


/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA224Test extends PHPUnit_Framework_TestCase
{
	public function testCreateFromAlgo() {
		$algo = new HMACWithSHA224AlgorithmIdentifier();
		$prf = PRF::fromAlgorithmIdentifier($algo);
		$this->assertInstanceOf(HMACSHA224::class, $prf);
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
