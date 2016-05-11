<?php

use CryptoUtil\PEM\PEM;


/**
 * @group pem
 */
class PEMTest extends PHPUnit_Framework_TestCase
{
	public function testFromString() {
		$str = file_get_contents(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pem = PEM::fromString($str);
		$this->assertInstanceOf(PEM::class, $pem);
	}
	
	public function testFromFile() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testFromFile
	 *
	 * @param PEM $pem
	 */
	public function testType(PEM $pem) {
		$this->assertEquals(PEM::TYPE_PRIVATE_KEY, $pem->type());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEM() {
		PEM::fromString("nope");
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEMData() {
		$str = <<<DATA
-----BEGIN TEST-----
%%%
-----END TEST-----
DATA;
		PEM::fromString($str);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testInvalidFile() {
		PEM::fromFile(TEST_ASSETS_DIR . "/nonexistent");
	}
}
