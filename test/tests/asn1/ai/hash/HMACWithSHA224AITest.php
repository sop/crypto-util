<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA224AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class HMACWithSHA224AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new HMACWithSHA224AlgorithmIdentifier();
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
		$this->assertInstanceOf(HMACWithSHA224AlgorithmIdentifier::class, $ai);
		return $ai;
	}
}
