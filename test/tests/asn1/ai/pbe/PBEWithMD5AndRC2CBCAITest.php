<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndRC2CBCAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class PBEWithMD5AndRC2CBCAITest extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const COUNT = 4096;
	
	public function testEncode() {
		$ai = new PBEWithMD5AndRC2CBCAlgorithmIdentifier(self::SALT, self::COUNT);
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
		$this->assertInstanceOf(PBEWithMD5AndRC2CBCAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai
	 */
	public function testSalt(PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::SALT, $ai->salt());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai
	 */
	public function testIterationCount(
		PBEWithMD5AndRC2CBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::COUNT, $ai->iterationCount());
	}
}
