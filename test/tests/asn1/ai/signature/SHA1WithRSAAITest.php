<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class SHA1WithRSAAITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new SHA1WithRSAEncryptionAlgorithmIdentifier();
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
		$this->assertInstanceOf(SHA1WithRSAEncryptionAlgorithmIdentifier::class, 
			$ai);
		return $ai;
	}
	
	/**
	 * @depends testEncode
	 * @expectedException UnexpectedValueException
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeNoParamsFail(Sequence $seq) {
		$seq = $seq->withoutElement(1);
		AlgorithmIdentifier::fromASN1($seq);
	}
	
	/**
	 * @depends testEncode
	 * @expectedException UnexpectedValueException
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeInvalidParamsFail(Sequence $seq) {
		$seq = $seq->withReplaced(1, new Sequence());
		AlgorithmIdentifier::fromASN1($seq);
	}
}
