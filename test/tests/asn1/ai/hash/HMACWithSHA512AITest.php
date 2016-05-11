<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA512AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class HMACWithSHA512AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new HMACWithSHA512AlgorithmIdentifier();
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
		$this->assertInstanceOf(HMACWithSHA512AlgorithmIdentifier::class, $ai);
		return $ai;
	}
}
