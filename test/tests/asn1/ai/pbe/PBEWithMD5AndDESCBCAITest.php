<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndDESCBCAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class PBEWithMD5AndDESCBCAITest extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const COUNT = 4096;
	
	public function testEncode() {
		$ai = new PBEWithMD5AndDESCBCAlgorithmIdentifier(self::SALT, self::COUNT);
		$seq = $ai->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq;
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param Sequence $seq
	 */
	public function testDecode(Sequence $seq) {
		$ai = AlgorithmIdentifier::fromASN1($seq);
		$this->assertInstanceOf(PBEWithMD5AndDESCBCAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithMD5AndDESCBCAlgorithmIdentifier $ai
	 */
	public function testSalt(PBEWithMD5AndDESCBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::SALT, $ai->salt());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithMD5AndDESCBCAlgorithmIdentifier $ai
	 */
	public function testIterationCount(
			PBEWithMD5AndDESCBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::COUNT, $ai->iterationCount());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param AlgorithmIdentifier $algo
	 */
	public function testName(AlgorithmIdentifier $algo) {
		$this->assertInternalType("string", $algo->name());
	}
}
