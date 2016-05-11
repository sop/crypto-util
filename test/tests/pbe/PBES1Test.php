<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\HashFunc\MD5;
use CryptoUtil\PBE\PBEKD\PBEKDF;
use CryptoUtil\PBE\PBES1;
use CryptoUtil\PBE\PBEScheme;


/**
 * @group pbe
 */
class PBES1Test extends PHPUnit_Framework_TestCase
{
	const SALT = "12345678";
	
	const ITER_COUNT = 8;
	
	const DATA = "DATA";
	
	const PASSWORD = "P4s5w0Rd";
	
	const KEY_16 = "0123456789abcdef";
	
	public function testCreate() {
		$pbes = new PBES1(new MD5(), new DESCBCAlgorithmIdentifier(), self::SALT, 
			self::ITER_COUNT, Crypto::getDefault());
		$this->assertInstanceOf(PBEScheme::class, $pbes);
		return $pbes;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBEScheme $pbes
	 */
	public function testEncrypt(PBEScheme $pbes) {
		$ciphertext = $pbes->encrypt(self::DATA, self::PASSWORD);
		$this->assertNotEquals(self::DATA, $ciphertext);
		return $ciphertext;
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncrypt
	 *
	 * @param PBEScheme $pbes
	 * @param string $ciphertext
	 */
	public function testDecrypt(PBEScheme $pbes, $ciphertext) {
		$data = $pbes->decrypt($ciphertext, self::PASSWORD);
		$this->assertEquals(self::DATA, $data);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBEScheme $pbes
	 */
	public function testEncryptWithKey(PBEScheme $pbes) {
		$ciphertext = $pbes->encryptWithKey(self::DATA, self::KEY_16);
		$this->assertNotEquals(self::DATA, $ciphertext);
		return $ciphertext;
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncryptWithKey
	 *
	 * @param PBEScheme $pbes
	 * @param string $ciphertext
	 */
	public function testDecryptWithKey(PBEScheme $pbes, $ciphertext) {
		$data = $pbes->decryptWithKey($ciphertext, self::KEY_16);
		$this->assertEquals(self::DATA, $data);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param PBEScheme $pbes
	 */
	public function testEncryptWithKeyInvalidSize(PBEScheme $pbes) {
		$pbes->encryptWithKey(self::DATA, "nope");
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param PBEScheme $pbes
	 */
	public function testDecryptWithKeyInvalidSize(PBEScheme $pbes) {
		$pbes->decryptWithKey(self::DATA, "nope");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBEScheme $pbes
	 */
	public function testKDF(PBEScheme $pbes) {
		$kdf = $pbes->kdf();
		$this->assertInstanceOf(PBEKDF::class, $kdf);
	}
}
