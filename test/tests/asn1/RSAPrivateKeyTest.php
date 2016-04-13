<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;


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
	}
	
	public function testFromPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pk = RSAPrivateKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPrivateKey::class, $pk);
	}
}
