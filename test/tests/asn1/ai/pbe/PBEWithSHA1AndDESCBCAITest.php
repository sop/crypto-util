<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndDESCBCAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class PBEWithSHA1AndDESCBCAITest extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const COUNT = 4096;
	
	public function testEncode() {
		$ai = new PBEWithSHA1AndDESCBCAlgorithmIdentifier(self::SALT, 
			self::COUNT);
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
		$this->assertInstanceOf(PBEWithSHA1AndDESCBCAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithSHA1AndDESCBCAlgorithmIdentifier $ai
	 */
	public function testSalt(PBEWithSHA1AndDESCBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::SALT, $ai->salt());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithSHA1AndDESCBCAlgorithmIdentifier $ai
	 */
	public function testIterationCount(
		PBEWithSHA1AndDESCBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::COUNT, $ai->iterationCount());
	}
}
