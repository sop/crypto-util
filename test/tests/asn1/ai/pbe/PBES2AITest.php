<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use ASN1\Type\Constructed\Sequence;


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

}
