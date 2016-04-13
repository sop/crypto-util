<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPublicKey;


/**
 * @group crypto
 */
class RSAPublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
		$pk = RSAPublicKey::fromDER($pem->data());
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
		return $pk;
	}
	
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
		$pk = RSAPublicKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
	}
	
	public function testFromPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$pk = RSAPublicKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
	}
}
