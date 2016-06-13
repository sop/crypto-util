<?php

use ASN1\Type\Primitive\Integer;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
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
		$pk = new ECPublicKey("\x04\0\0");
		$pk->publicKeyInfo();
	}
	
	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testInvalidECPoint() {
		new ECPublicKey("\x0");
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
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testCurvePoint(ECPublicKey $pk) {
		list($x, $y) = $pk->curvePoint();
		$this->assertInstanceOf(Integer::class, $x);
		$this->assertInstanceOf(Integer::class, $y);
		return [$x, $y];
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testHasNamedCurve(ECPublicKey $pk) {
		$this->assertTrue($pk->hasNamedCurve());
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param ECPublicKey $pk
	 */
	public function testNamedCurve(ECPublicKey $pk) {
		$this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, 
			$pk->namedCurve());
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoCurveFail() {
		$pk = new ECPublicKey("\x4\0\0");
		$pk->namedCurve();
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testCompressedFail() {
		$pk = new ECPublicKey("\x3\0");
		$pk->curvePoint();
	}
	
	/**
	 * @depends testCurvePoint
	 */
	public function testFromCoordinates(array $points) {
		$x = $points[0]->number();
		$y = $points[1]->number();
		$pk = ECPublicKey::fromCoordinates($x, $y, 
			ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
		$this->assertInstanceOf(ECPublicKey::class, $pk);
		return $pk;
	}
	
	/**
	 * @depends testFromPEM
	 * @depends testFromCoordinates
	 *
	 * @param ECPublicKey $ref
	 * @param ECPublicKey $new
	 */
	public function testFromCoordsEqualsPEM(ECPublicKey $ref, ECPublicKey $new) {
		$this->assertEquals($ref, $new);
	}
}
