<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA384AlgorithmIdentifier;
use CryptoUtil\PBE\PRF\HMACSHA384;
use CryptoUtil\PBE\PRF\PRF;


/**
 * @group pbe
 * @group prf
 */
class PRFHMACSHA384Test extends PHPUnit_Framework_TestCase
{
	public function testCreateFromAlgo() {
		$algo = new HMACWithSHA384AlgorithmIdentifier();
		$prf = PRF::fromAlgorithmIdentifier($algo);
		$this->assertInstanceOf(HMACSHA384::class, $prf);
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
