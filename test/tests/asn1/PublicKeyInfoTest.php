<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\RSA\RSAEncryptionAlgorithmIdentifier;


/**
 * @group asn1
 */
class PubliceKeyInfoTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$pki = PublicKeyInfo::fromDER($pem->data());
		$this->assertInstanceOf(PublicKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PublicKeyInfo $pki
	 */
	public function testAlgoObj(PublicKeyInfo $pki) {
		$ref = new RSAEncryptionAlgorithmIdentifier();
		$algo = $pki->algorithmIdentifier();
		$this->assertEquals($ref, $algo);
		return $algo;
	}
	
	/**
	 * @depends testAlgoObj
	 *
	 * @param AlgorithmIdentifier $algo
	 */
	public function testAlgoOID(AlgorithmIdentifier $algo) {
		$this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, 
			$algo->oid());
	}
	
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$pki = PublicKeyInfo::fromPEM($pem);
		$this->assertInstanceOf(PublicKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param PublicKeyInfo $pki
	 */
	public function testToPEM(PublicKeyInfo $pki) {
		$pem = $pki->toPEM();
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testRecodedPEM(PEM $pem) {
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$this->assertEquals($ref, $pem);
	}
}
