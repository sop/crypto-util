<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


/**
 * @group asn1
 * @group algo-id
 */
class PBEKDF2AITest extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const COUNT = 4096;
	
	const KEY_LEN = 8;
	
	public function testEncode() {
		$ai = new PBKDF2AlgorithmIdentifier(self::SALT, self::COUNT, 
			self::KEY_LEN);
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
		$this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBKDF2AlgorithmIdentifier $ai
	 */
	public function testSalt(PBKDF2AlgorithmIdentifier $ai) {
		$this->assertEquals(self::SALT, $ai->salt());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBKDF2AlgorithmIdentifier $ai
	 */
	public function testIterationCount(PBKDF2AlgorithmIdentifier $ai) {
		$this->assertEquals(self::COUNT, $ai->iterationCount());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBKDF2AlgorithmIdentifier $ai
	 */
	public function testKeyLength(PBKDF2AlgorithmIdentifier $ai) {
		$this->assertEquals(self::KEY_LEN, $ai->keyLength());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBKDF2AlgorithmIdentifier $ai
	 */
	public function testPRF(PBKDF2AlgorithmIdentifier $ai) {
		$algo = $ai->prfAlgorithmIdentifier();
		$this->assertInstanceOf(PRFAlgorithmIdentifier::class, $algo);
	}
}
