<?php

use CryptoUtil\PBE\PBEKD\PBEKDF;
use CryptoUtil\PBE\PBEKD\PBEKDF2;
use CryptoUtil\PBE\PRF\HMACSHA1;


/**
 * @group pbe
 * @group kdf
 */
class PBEKDF2Test extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$kdf = new PBEKDF2(new HMACSHA1());
		$this->assertInstanceOf(PBEKDF::class, $kdf);
		return $kdf;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBEKDF $kdf
	 */
	public function testDerive(PBEKDF $kdf) {
		$key = $kdf->derive("password", "salt", 8, 16);
		$this->assertEquals(16, strlen($key));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBEKDF $kdf
	 */
	public function testDeriveLong(PBEKDF $kdf) {
		$key = $kdf->derive("password", "salt", 8, 256);
		$this->assertEquals(256, strlen($key));
	}
}
