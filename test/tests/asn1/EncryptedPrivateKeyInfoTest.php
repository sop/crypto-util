<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use CryptoUtil\ASN1\EncryptedPrivateKeyInfo;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\PBEScheme;
use CryptoUtil\PEM\PEM;


/**
 * @group asn1
 * @group privatekey
 */
class EncryptedPrivateKeyInfoTest extends PHPUnit_Framework_TestCase
{
	const PASSWORD = "password";
	
	private static $_pem_v1;
	
	private static $_pem_v2;
	
	public static function setUpBeforeClass() {
		self::$_pem_v1 = PEM::fromFile(
			TEST_ASSETS_DIR . "/rsa/encrypted_private_key.pem");
		self::$_pem_v2 = PEM::fromFile(
			TEST_ASSETS_DIR . "/rsa/encrypted_private_key_v2.pem");
	}
	
	public static function tearDownAfterClass() {
		self::$_pem_v1 = null;
		self::$_pem_v2 = null;
	}
	
	public function testFromPEM() {
		$epki = EncryptedPrivateKeyInfo::fromPEM(self::$_pem_v1);
		$this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
		return $epki;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param EncryptedPrivateKeyInfo $refkey
	 */
	public function testCreate(EncryptedPrivateKeyInfo $refkey) {
		$salt = $refkey->encryptionAlgorithm()->salt();
		$count = $refkey->encryptionAlgorithm()->iterationCount();
		$pki = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		$algo = new PBEWithSHA1AndRC2CBCAlgorithmIdentifier($salt, $count);
		$epki = EncryptedPrivateKeyInfo::encryptPrivateKeyInfo($pki, $algo, 
			self::PASSWORD, Crypto::getDefault());
		$this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
		return $epki;
	}
	
	/**
	 * Test that encrypt implementation produces key identical to reference
	 *
	 * @depends testFromPEM
	 * @depends testCreate
	 *
	 * @param EncryptedPrivateKeyInfo $epki
	 */
	public function testEqualsToRef(EncryptedPrivateKeyInfo $ref, 
			EncryptedPrivateKeyInfo $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param EncryptedPrivateKeyInfo $epki
	 */
	public function testDecrypt(EncryptedPrivateKeyInfo $epki) {
		$pki = $epki->decryptPrivateKeyInfo(self::PASSWORD, 
			Crypto::getDefault());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param EncryptedPrivateKeyInfo $epki
	 */
	public function testDecryptFail(EncryptedPrivateKeyInfo $epki) {
		$epki->decryptPrivateKeyInfo("nope", Crypto::getDefault());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param EncryptedPrivateKeyInfo $epki
	 */
	public function testToPEM(EncryptedPrivateKeyInfo $epki) {
		$pem = $epki->toPEM();
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testPEMEqualsToRef(PEM $pem) {
		$this->assertEquals(self::$_pem_v1, $pem);
	}
	
	public function testV2FromPEM() {
		$epki = EncryptedPrivateKeyInfo::fromPEM(self::$_pem_v2);
		$this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
		return $epki;
	}
	
	/**
	 * @depends testV2FromPEM
	 *
	 * @param EncryptedPrivateKeyInfo $refkey
	 */
	public function testCreateV2(EncryptedPrivateKeyInfo $refkey) {
		$salt = $refkey->encryptionAlgorithm()->salt();
		$count = $refkey->encryptionAlgorithm()->iterationCount();
		$iv = $refkey->encryptionAlgorithm()
			->esAlgorithmIdentifier()
			->initializationVector();
		$pki = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		$algo = new PBES2AlgorithmIdentifier(
			new PBKDF2AlgorithmIdentifier($salt, $count), 
			new DESEDE3CBCAlgorithmIdentifier($iv));
		$epki = EncryptedPrivateKeyInfo::encryptPrivateKeyInfo($pki, $algo, 
			self::PASSWORD, Crypto::getDefault());
		$this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
		return $epki;
	}
	
	/**
	 * @depends testV2FromPEM
	 * @depends testCreateV2
	 *
	 * @param EncryptedPrivateKeyInfo $ref
	 * @param EncryptedPrivateKeyInfo $new
	 */
	public function testV2EqualsToRef(EncryptedPrivateKeyInfo $ref, 
			EncryptedPrivateKeyInfo $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreateV2
	 *
	 * @param EncryptedPrivateKeyInfo $epki
	 */
	public function testDecryptV2(EncryptedPrivateKeyInfo $epki) {
		$pki = $epki->decryptPrivateKeyInfo(self::PASSWORD, 
			Crypto::getDefault());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testV2FromPEM
	 *
	 * @param EncryptedPrivateKeyInfo $ref
	 */
	public function testEncryptWithKey(EncryptedPrivateKeyInfo $refkey) {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromPEM($pem);
		$salt = $refkey->encryptionAlgorithm()->salt();
		$count = $refkey->encryptionAlgorithm()->iterationCount();
		$iv = $refkey->encryptionAlgorithm()
			->esAlgorithmIdentifier()
			->initializationVector();
		$algo = new PBES2AlgorithmIdentifier(
			new PBKDF2AlgorithmIdentifier($salt, $count), 
			new DESEDE3CBCAlgorithmIdentifier($iv));
		$scheme = PBEScheme::fromAlgorithmIdentifier($algo, 
			Crypto::getDefault());
		$key = $scheme->kdf()->derive(self::PASSWORD, $salt, $count, 
			$algo->esAlgorithmIdentifier()
				->keySize());
		$epki = EncryptedPrivateKeyInfo::encryptPrivateKeyInfoWithDerivedKey(
			$pki, $algo, $key, Crypto::getDefault());
		$this->assertEquals($refkey, $epki);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidAlgo() {
		$seq = new Sequence(new Sequence(new ObjectIdentifier("1.3.6.1.3")), 
			new OctetString(""));
		EncryptedPrivateKeyInfo::fromASN1($seq);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEMType() {
		$pem = new PEM("nope", "");
		EncryptedPrivateKeyInfo::fromPEM($pem);
	}
}
