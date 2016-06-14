<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\EC\ECDSASigValue;


/**
 * @group asn1
 * @group ec
 */
class ECDSASigValueTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$sig = new ECDSASigValue("123456789", "987654321");
		$this->assertInstanceOf(ECDSASigValue::class, $sig);
		return $sig;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ECDSASigValue $sig
	 */
	public function testEncode(ECDSASigValue $sig) {
		$el = $sig->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ECDSASigValue $sig
	 */
	public function testToDER(ECDSASigValue $sig) {
		$der = $sig->toDER();
		$this->assertInternalType("string", $der);
		return $der;
	}
	
	/**
	 * @depends testToDER
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$sig = ECDSASigValue::fromDER($data);
		$this->assertInstanceOf(ECDSASigValue::class, $sig);
		return $sig;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param ECDSASigValue $ref
	 * @param ECDSASigValue $sig
	 */
	public function testRecoded(ECDSASigValue $ref, ECDSASigValue $sig) {
		$this->assertEquals($ref, $sig);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ECDSASigValue $sig
	 */
	public function testRValue(ECDSASigValue $sig) {
		$this->assertEquals("123456789", $sig->r());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ECDSASigValue $sig
	 */
	public function testSValue(ECDSASigValue $sig) {
		$this->assertEquals("987654321", $sig->s());
	}
}
