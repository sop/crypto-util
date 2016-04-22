<?php

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\EC\ECPrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\PEM\PEM;


/**
 * @group asn1
 * @group privatekey
 */
class PrivateKeyInfoTest extends PHPUnit_Framework_TestCase
{
	public function testDecodeRSA() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromDER($pem->data());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testDecodeRSA
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testAlgoObj(PrivateKeyInfo $pki) {
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
	
	/**
	 * @depends testDecodeRSA
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testGetRSAPrivateKey(PrivateKeyInfo $pki) {
		$pk = $pki->privateKey();
		$this->assertInstanceOf(RSAPrivateKey::class, $pk);
	}
	
	public function testDecodeEC() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem");
		$pki = PrivateKeyInfo::fromDER($pem->data());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testDecodeEC
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testGetECPrivateKey(PrivateKeyInfo $pki) {
		$pk = $pki->privateKey();
		$this->assertInstanceOf(ECPrivateKey::class, $pk);
		return $pk;
	}
	
	/**
	 * @depends testGetECPrivateKey
	 * 
	 * @param ECPrivateKey $pk
	 */
	public function testECPrivateKeyHasNamedCurve(ECPrivateKey $pk) {
		$this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, 
			$pk->namedCurve());
	}
	
	public function testFromRSAPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromPEM($pem);
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testFromRSAPEM
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
