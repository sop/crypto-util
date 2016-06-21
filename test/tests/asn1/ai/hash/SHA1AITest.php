<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\NullType;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class SHA1AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new SHA1AlgorithmIdentifier();
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
		$this->assertInstanceOf(SHA1AlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeWithParams(Sequence $seq) {
		$seq = $seq->withInserted(1, new NullType());
		$ai = AlgorithmIdentifier::fromASN1($seq);
		$this->assertInstanceOf(SHA1AlgorithmIdentifier::class, $ai);
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
