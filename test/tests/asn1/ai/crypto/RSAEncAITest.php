<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


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
}
