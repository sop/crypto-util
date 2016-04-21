<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class RC2CBCAITest extends PHPUnit_Framework_TestCase
{
	const IV = "12345678";
	
	public function testEncode() {
		$ai = new RC2CBCAlgorithmIdentifier(64, self::IV);
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
		$this->assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param RC2CBCAlgorithmIdentifier $ai
	 */
	public function testIV(RC2CBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::IV, $ai->initializationVector());
	}
}
