<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * @group asn1
 */
class PrivateKeyInfoTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromDER($pem->data());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testAlgoOID(PrivateKeyInfo $pki) {
		$this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, 
			$pki->algorithmIdentifier()
				->oid());
	}
	
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromPEM($pem);
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testToPEM(PrivateKeyInfo $pki) {
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
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$this->assertEquals($ref, $pem);
	}
}
