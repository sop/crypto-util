<?php

use CryptoUtil\PBE\HashFunc\MD5;
use CryptoUtil\PBE\PBEKD\PBEKDF;
use CryptoUtil\PBE\PBEKD\PBEKDF1;


/**
 * @group pbe
 * @group kdf
 */
class PBEKDF1Test extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$kdf = new PBEKDF1(new MD5());
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
	public function testDeriveShort(PBEKDF $kdf) {
		$key = $kdf->derive("password", "salt", 8, 10);
		$this->assertEquals(10, strlen($key));
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param PBEKDF $kdf
	 */
	public function testKeyTooLong(PBEKDF $kdf) {
		$kdf->derive("password", "salt", 1, 17);
	}
}
