<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class ECPKAITest extends PHPUnit_Framework_TestCase
{
	const OID = "1.2.840.10045.3.1.7";
	
	public function testEncode() {
		$ai = new ECPublicKeyAlgorithmIdentifier(self::OID);
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
		$this->assertInstanceOf(ECPublicKeyAlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 * 
	 * @param ECPublicKeyAlgorithmIdentifier $ai
	 */
	public function testNamedCurve(ECPublicKeyAlgorithmIdentifier $ai) {
		$this->assertEquals(self::OID, $ai->namedCurve());
	}
}
