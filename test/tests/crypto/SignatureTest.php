<?php

use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\Crypto\Signature;


/**
 * @group crypto
 */
class SignatureTest extends PHPUnit_Framework_TestCase
{
	const BYTES = "01234567";
	
	public function testCreate() {
		$signature = Signature::fromASN1(new BitString(self::BYTES));
		$this->assertInstanceOf(Signature::class, $signature);
		return $signature;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Signature $signature
	 */
	public function testOctets(Signature $signature) {
		$this->assertEquals(self::BYTES, $signature->octets());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Signature $signature
	 */
	public function testToOctetString(Signature $signature) {
		$el = $signature->toOctetString();
		$this->assertInstanceOf(OctetString::class, $el);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Signature $signature
	 */
	public function testToBitString(Signature $signature) {
		$el = $signature->toBitString();
		$this->assertInstanceOf(BitString::class, $el);
	}
}
