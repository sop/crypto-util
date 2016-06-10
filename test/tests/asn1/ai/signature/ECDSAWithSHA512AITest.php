<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class ECDSAWithSHA512AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new ECDSAWithSHA512AlgorithmIdentifier();
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
		$this->assertInstanceOf(ECDSAWithSHA512AlgorithmIdentifier::class, $ai);
		return $ai;
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
