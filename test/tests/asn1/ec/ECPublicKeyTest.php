<?php

use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\PEM\PEM;


/**
 * @group asn1
 * @group ec
 */
class ECPublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
		$pk = ECPublicKey::fromPEM($pem);
		$this->assertInstanceOf(ECPublicKey::class, $pk);
		return $pk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testECPoint(ECPublicKey $pk) {
		$this->assertNotEmpty($pk->ECPoint());
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testPublicKeyInfo(ECPublicKey $pk) {
		$pki = $pk->publicKeyInfo();
		$this->assertInstanceOf(PublicKeyInfo::class, $pki);
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoNamedCurve() {
		$pk = new ECPublicKey("\0");
		$pk->publicKeyInfo();
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEMType() {
		$pem = new PEM("nope", "");
		ECPublicKey::fromPEM($pem);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testRSAKeyFail() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		ECPublicKey::fromPEM($pem);
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testToDER(ECPublicKey $pk) {
		$this->assertNotEmpty($pk->toDER());
	}
}
