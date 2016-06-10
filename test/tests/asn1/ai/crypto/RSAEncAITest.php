<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class RSAEncAITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$ai = new RSAEncryptionAlgorithmIdentifier();
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
		$this->assertInstanceOf(RSAEncryptionAlgorithmIdentifier::class, $ai);
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
	 * @depends testDecode
	 *
	 * @param AlgorithmIdentifier $algo
	 */
	public function testName(AlgorithmIdentifier $algo) {
		$this->assertInternalType("string", $algo->name());
	}
}
