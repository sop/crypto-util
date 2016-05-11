<?php

use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\RSA\RSAPublicKey;
use CryptoUtil\PEM\PEM;


/**
 * @group asn1
 * @group publickey
 */
class PublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testFromRSAPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
		$pk = PublicKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
	}
	
	public function testFromRSAPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$pk = PublicKey::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKey::class, $pk);
	}
	
	public function testFromECPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
		$pk = PublicKey::fromPEM($pem);
		$this->assertInstanceOf(ECPublicKey::class, $pk);
		return $pk;
	}
	
	public function testRSAPKIRecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
		$this->assertEquals($pem, $result);
	}
	
	public function testECPKIRecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
		$result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
		$this->assertEquals($pem, $result);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEM() {
		$pem = new PEM("nope", "");
		PublicKey::fromPEM($pem);
	}
}
