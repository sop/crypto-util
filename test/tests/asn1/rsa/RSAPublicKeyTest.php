<?php

use CryptoUtil\ASN1\RSA\RSAPublicKey;
use CryptoUtil\PEM\PEM;


/**
 * @group asn1
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
		return $pk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param RSAPublicKey $pk
	 */
	public function testToPEM(RSAPublicKey $pk) {
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
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
		$this->assertEquals($ref, $pem);
	}
	
	public function testFromPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$pk = RSAPublicKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEMType() {
		$pem = new PEM("nope", "");
		RSAPublicKey::fromPEM($pem);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testECKeyFail() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
		RSAPublicKey::fromPEM($pem);
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param RSAPublicKey $pk
	 */
	public function testModulus(RSAPublicKey $pk) {
		$this->assertNotEmpty($pk->modulus());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param RSAPublicKey $pk
	 */
	public function testPublicExponent(RSAPublicKey $pk) {
		$this->assertNotEmpty($pk->publicExponent());
	}
}
