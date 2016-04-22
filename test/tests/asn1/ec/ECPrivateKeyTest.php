<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\EC\ECPrivateKey;
use CryptoUtil\ASN1\EC\ECPublicKey;


/**
 * @group asn1
 * @group ec
 */
class ECPrivateKeyTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/ec_private_key.pem");
		$pk = ECPrivateKey::fromDER($pem->data());
		$this->assertInstanceOf(ECPrivateKey::class, $pk);
		return $pk;
	}
	
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/ec_private_key.pem");
		$pk = ECPrivateKey::fromPEM($pem);
		$this->assertInstanceOf(ECPrivateKey::class, $pk);
		return $pk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPrivateKey $pk
	 */
	public function testToPEM(ECPrivateKey $pk) {
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
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/ec/ec_private_key.pem");
		$this->assertEquals($ref, $pem);
	}
	
	public function testFromPKIPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem");
		$pk = ECPrivateKey::fromPEM($pem);
		$this->assertInstanceOf(ECPrivateKey::class, $pk);
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param ECPrivateKey $pk
	 */
	public function testGetPublicKey(ECPrivateKey $pk) {
		$pub = $pk->publicKey();
		$ref = ECPublicKey::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem"));
		$this->assertEquals($ref, $pub);
	}
}
