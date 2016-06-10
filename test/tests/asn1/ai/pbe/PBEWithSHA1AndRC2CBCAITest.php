<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class PBEWithSHA1AndRC2CBCAITest extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const COUNT = 4096;
	
	public function testEncode() {
		$ai = new PBEWithSHA1AndRC2CBCAlgorithmIdentifier(self::SALT, 
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
		$this->assertInstanceOf(PBEWithSHA1AndRC2CBCAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithSHA1AndRC2CBCAlgorithmIdentifier $ai
	 */
	public function testSalt(PBEWithSHA1AndRC2CBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::SALT, $ai->salt());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithSHA1AndRC2CBCAlgorithmIdentifier $ai
	 */
	public function testIterationCount(
			PBEWithSHA1AndRC2CBCAlgorithmIdentifier $ai) {
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
