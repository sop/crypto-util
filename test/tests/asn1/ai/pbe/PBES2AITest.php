<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class PBES2AITest extends PHPUnit_Framework_TestCase
{
	public function testEncode() {
		$kdf = new PBKDF2AlgorithmIdentifier("12345678", 1024);
		$es = new DESCBCAlgorithmIdentifier("fedcba98");
		$ai = new PBES2AlgorithmIdentifier($kdf, $es);
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
		$this->assertInstanceOf(PBES2AlgorithmIdentifier::class, $ai);
		return $ai;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBES2AlgorithmIdentifier $ai
	 */
	public function testKDF(PBES2AlgorithmIdentifier $ai) {
		$this->assertInstanceOf(PBKDF2AlgorithmIdentifier::class, 
			$ai->kdfAlgorithmIdentifier());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PBES2AlgorithmIdentifier $ai
	 */
	public function testES(PBES2AlgorithmIdentifier $ai) {
		$this->assertInstanceOf(CipherAlgorithmIdentifier::class, 
			$ai->esAlgorithmIdentifier());
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
	public function testDecodeInvalidKDFFail(Sequence $seq) {
		$params = $seq->at(1);
		$ai = $params->at(0)->withReplaced(0, new ObjectIdentifier("1.3.6.1.3"));
		$params = $params->withReplaced(0, $ai);
		$seq = $seq->withReplaced(1, $params);
		AlgorithmIdentifier::fromASN1($seq);
	}
	
	/**
	 * @depends testEncode
	 * @expectedException UnexpectedValueException
	 *
	 * @param Sequence $seq
	 */
	public function testDecodeInvalidCipherFail(Sequence $seq) {
		$params = $seq->at(1);
		$ai = $params->at(1)->withReplaced(0, new ObjectIdentifier("1.3.6.1.3"));
		$params = $params->withReplaced(1, $ai);
		$seq = $seq->withReplaced(1, $params);
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
