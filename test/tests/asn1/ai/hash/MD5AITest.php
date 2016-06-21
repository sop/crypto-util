<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class MD5AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new MD5AlgorithmIdentifier();
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
		$this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeWithoutParams(Sequence $seq) {
		$seq = $seq->withoutElement(1);
		$ai = AlgorithmIdentifier::fromASN1($seq);
		$this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
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
