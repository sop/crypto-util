<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\ASN1\RSA\RSAPublicKey;


/**
 * @group crypto
 */
class RSAPrivateKeyTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
		$pk = RSAPrivateKey::fromDER($pem->data());
		$this->assertInstanceOf(RSAPrivateKey::class, $pk);
		return $pk;
	}
	
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
		$pk = RSAPrivateKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPrivateKey::class, $pk);
		return $pk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param RSAPrivateKey $pk
	 */
	public function testToPEM(RSAPrivateKey $pk) {
		$pem = $pk->toPEM();
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testRecodedPEM(PEM $pem) {
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
		$this->assertEquals($ref, $pem);
	}
	
	public function testFromPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pk = RSAPrivateKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPrivateKey::class, $pk);
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param RSAPrivateKey $pk
	 */
	public function testGetPublicKey(RSAPrivateKey $pk) {
		$pub = $pk->publicKey();
		$ref = RSAPublicKey::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem"));
		$this->assertEquals($ref, $pub);
	}
}
