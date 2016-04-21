<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class DESCBCAITest extends PHPUnit_Framework_TestCase
{
	const IV = "12345678";
	
	public function testEncode() {
		$ai = new DESCBCAlgorithmIdentifier(self::IV);
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
		$this->assertInstanceOf(DESCBCAlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param DESCBCAlgorithmIdentifier $ai
	 */
	public function testIV(DESCBCAlgorithmIdentifier $ai) {
		$this->assertEquals(self::IV, $ai->initializationVector());
	}
}
