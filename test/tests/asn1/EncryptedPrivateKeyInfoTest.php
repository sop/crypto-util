<?php

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
	
	public function testFromPEM() {
		$epki = EncryptedPrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/encrypted_private_key.pem"));
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
	
	public function testV2FromPEM() {
		$epki = EncryptedPrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/encrypted_private_key_v2.pem"));
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
}
