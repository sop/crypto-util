<?php

use CryptoUtil\PBE\HashFunc\HashFunc;
use CryptoUtil\PBE\HashFunc\MD5;


/**
 * @group pbe
 * @group hash
 */
class PBEMD5Test extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$func = new MD5();
		$this->assertInstanceOf(HashFunc::class, $func);
		return $func;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param HashFunc $func
	 */
	public function testLength(HashFunc $func) {
		$this->assertEquals(16, $func->length());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param HashFunc $func
	 */
	public function testHash(HashFunc $func) {
		static $data = "DATA";
		$expected = md5($data, true);
		$this->assertEquals($expected, $func($data));
	}
}
