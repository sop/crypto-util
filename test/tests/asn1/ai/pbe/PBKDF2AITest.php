<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\PRFAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;


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
	 * @expectedException LogicException
	 */
	public function testKeyLengthFails() {
		$ai = new PBKDF2AlgorithmIdentifier("\0", 1);
		$ai->keyLength();
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
	
	public function testEncodeExplicitPRF() {
		$ai = new PBKDF2AlgorithmIdentifier(self::SALT, self::COUNT, 
			self::KEY_LEN, new HMACWithSHA256AlgorithmIdentifier());
		$seq = $ai->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq;
	}
	
	/**
	 * @depends testEncodeExplicitPRF
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeExplicitPRF(Sequence $seq) {
		$ai = AlgorithmIdentifier::fromASN1($seq);
		$this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecodeExplicitPRF
	 *
	 * @param PBKDF2AlgorithmIdentifier $ai
	 */
	public function testExplicitPRF(PBKDF2AlgorithmIdentifier $ai) {
		$this->assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, 
			$ai->prfAlgorithmIdentifier());
	}
	
	/**
	 * @depends testEncode
	 * @expectedException UnexpectedValueException
	 *
	 * @param Sequence $seq
	 */
	public function testInvalidPRF(Sequence $seq) {
		$prf = new Sequence(new ObjectIdentifier("1.3.6.1.3"));
		$params = $seq->at(1);
		$params = $params->withInserted(3, $prf);
		$seq = $seq->withReplaced(1, $params);
		AlgorithmIdentifier::fromASN1($seq);
	}
}
