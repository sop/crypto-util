<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD4WithRSAEncryptionAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class MD4WithRSAAITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new MD4WithRSAEncryptionAlgorithmIdentifier();
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
		$this->assertInstanceOf(MD4WithRSAEncryptionAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
}
