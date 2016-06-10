<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class AlgorithmIdentifierTest extends PHPUnit_Framework_TestCase
{
	private static $_unknownASN1;
	
	public static function setUpBeforeClass() {
		self::$_unknownASN1 = new Sequence(
			new ObjectIdentifier("1.3.6.1.3", new NullType()));
	}
	
	public static function tearDownAfterClass() {
		self::$_unknownASN1 = null;
	}
	
	public function testFromUnknownASN1() {
		$ai = AlgorithmIdentifier::fromASN1(self::$_unknownASN1);
		$this->assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testFromUnknownASN1
	 *
	 * @param GenericAlgorithmIdentifier $ai
	 */
	public function testEncodeUnknown(GenericAlgorithmIdentifier $ai) {
		$seq = $ai->toASN1();
		$this->assertEquals(self::$_unknownASN1, $seq);
	}
	
	/**
	 * @expectedException BadMethodCallException
	 */
	public function testSpecificAlgoBadCall() {
		$cls = new ReflectionClass(SpecificAlgorithmIdentifier::class);
		$mtd = $cls->getMethod("_fromASN1Params");
		$mtd->setAccessible(true);
		$mtd->invoke(null);
	}
	
	/**
	 * @depends testFromUnknownASN1
	 *
	 * @param AlgorithmIdentifier $algo
	 */
	public function testName(AlgorithmIdentifier $algo) {
		$this->assertInternalType("string", $algo->name());
	}
}
