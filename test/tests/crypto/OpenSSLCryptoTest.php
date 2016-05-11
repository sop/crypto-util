<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD2WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD4WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\Crypto\OpenSSLCrypto;
use CryptoUtil\Crypto\Signature;
use CryptoUtil\PEM\PEM;


/**
 * @group crypto
 */
class OpenSSLCryptoTest extends PHPUnit_Framework_TestCase
{
	const DATA = "PAYLOAD";
	
	private static $_crypto;
	
	private static $_rsaPrivKeyInfo;
	
	private static $_ecPrivKeyInfo;
	
	public static function setUpBeforeClass() {
		self::$_crypto = new OpenSSLCrypto();
		self::$_rsaPrivKeyInfo = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		self::$_ecPrivKeyInfo = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_crypto = null;
		self::$_rsaPrivKeyInfo = null;
		self::$_ecPrivKeyInfo = null;
	}
	
	/**
	 * @dataProvider provideSignAndVerifyRSA
	 *
	 * @param SignatureAlgorithmIdentifier $algo
	 */
	public function testSignAndVerifyRSA(SignatureAlgorithmIdentifier $algo) {
		$signature = self::$_crypto->sign(self::DATA, self::$_rsaPrivKeyInfo, 
			$algo);
		$this->assertInstanceOf(Signature::class, $signature);
		$pubkey_info = self::$_rsaPrivKeyInfo->privateKey()
			->publicKey()
			->publicKeyInfo();
		$result = self::$_crypto->verify(self::DATA, $signature, $pubkey_info, 
			$algo);
		$this->assertTrue($result);
	}
	
	public function provideSignAndVerifyRSA() {
		return array(
			/* @formatter:off */
			[new MD4WithRSAEncryptionAlgorithmIdentifier()],
			[new MD5WithRSAEncryptionAlgorithmIdentifier()],
			[new SHA1WithRSAEncryptionAlgorithmIdentifier()],
			[new SHA224WithRSAEncryptionAlgorithmIdentifier()],
			[new SHA256WithRSAEncryptionAlgorithmIdentifier()],
			[new SHA384WithRSAEncryptionAlgorithmIdentifier()],
			[new SHA512WithRSAEncryptionAlgorithmIdentifier()]
			/* @formatter:on */
		);
	}
	
	/**
	 * @dataProvider provideSignAndVerifyEC
	 *
	 * @param SignatureAlgorithmIdentifier $algo
	 */
	public function testSignAndVerifyEC(SignatureAlgorithmIdentifier $algo) {
		$signature = self::$_crypto->sign(self::DATA, self::$_ecPrivKeyInfo, 
			$algo);
		$this->assertInstanceOf(Signature::class, $signature);
		$pubkey_info = self::$_ecPrivKeyInfo->privateKey()
			->publicKey()
			->publicKeyInfo();
		$result = self::$_crypto->verify(self::DATA, $signature, $pubkey_info, 
			$algo);
		$this->assertTrue($result);
	}
	
	public function provideSignAndVerifyEC() {
		return array(
			/* @formatter:off */
			[new ECDSAWithSHA1AlgorithmIdentifier()]
			/* @formatter:on */
		);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedDigestFail() {
		$algo = new MD2WithRSAEncryptionAlgorithmIdentifier();
		self::$_crypto->sign(self::DATA, self::$_rsaPrivKeyInfo, $algo);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testSignInvalidKeyFails() {
		$pk = new RSAPrivateKey(0, 0, 0, 0, 0, 0, 0, 0);
		$algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
		self::$_crypto->sign(self::DATA, $pk->privateKeyInfo(), $algo);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testVerifyInvalidKeyFails() {
		$signature = new Signature("");
		$algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
		$pk = self::$_ecPrivKeyInfo->privateKey()->publicKey();
		self::$_crypto->verify(self::DATA, $signature, $pk->publicKeyInfo(), 
			$algo);
	}
	
	/**
	 * @dataProvider provideEncryptAndDecrypt
	 *
	 * @param string $data
	 * @param CipherAlgorithmIdentifier $algo
	 * @param string $key
	 */
	public function testEncryptAndDecrypt($data, CipherAlgorithmIdentifier $algo, 
			$key) {
		$ciphertext = self::$_crypto->encrypt($data, $key, $algo);
		$this->assertNotEquals($data, $ciphertext);
		$plaintext = self::$_crypto->decrypt($ciphertext, $key, $algo);
		$this->assertEquals($data, $plaintext);
	}
	
	public function provideEncryptAndDecrypt() {
		$data8 = "12345678";
		$iv8 = hex2bin("8877665544332211");
		$key5 = hex2bin("1122334455");
		$key8 = hex2bin("1122334455667788");
		$key16 = str_repeat($key8, 2);
		$key24 = str_repeat($key8, 3);
		return array(
			/* @formatter:off */
			[$data8, new DESCBCAlgorithmIdentifier($iv8), $key8],
			[$data8, new DESEDE3CBCAlgorithmIdentifier($iv8), $key24],
			[$data8, new RC2CBCAlgorithmIdentifier(40, $iv8), $key5],
			[$data8, new RC2CBCAlgorithmIdentifier(64, $iv8), $key8],
			[$data8, new RC2CBCAlgorithmIdentifier(128, $iv8), $key16],
			/* @formatter:on */
		);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedRC2KeySize() {
		$data = "12345678";
		$key = "12345678";
		$algo = new RC2CBCAlgorithmIdentifier(1, "87654321");
		self::$_crypto->encrypt($data, $key, $algo);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testEncryptUnalignedFail() {
		$data = "1234567";
		$key = "12345678";
		$algo = new DESCBCAlgorithmIdentifier("87654321");
		self::$_crypto->encrypt($data, $key, $algo);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDecryptUnalignedFail() {
		$data = "1234567";
		$key = "12345678";
		$algo = new DESCBCAlgorithmIdentifier("87654321");
		self::$_crypto->decrypt($data, $key, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedCipherFail() {
		self::$_crypto->encrypt(self::DATA, "", 
			new OpenSSLCryptoTest_UnsupportedCipher());
	}
}


class OpenSSLCryptoTest_UnsupportedCipher extends CipherAlgorithmIdentifier
{
	public function __construct() {
		$this->_oid = "1.3.6.1.3";
	}
	
	public function keySize() {
		return 1;
	}
	
	protected function _paramsASN1() {
		return null;
	}
}
