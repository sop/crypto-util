<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA384AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use CryptoUtil\ASN1\AlgorithmIdentifier\SpecificAlgorithmIdentifier;


/**
 * @group asn1
 * @group algo-id
 */
class SignatureFactoryTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @dataProvider provideAlgoForAsymmetricCrypto
	 *
	 * @param AsymmetricCryptoAlgorithmIdentifier $crypto_algo
	 * @param HashAlgorithmIdentifier $hash_algo
	 * @param string $expected_class
	 */
	public function testAlgoForAsymmetricCrypto($crypto_algo, $hash_algo, 
			$expected_class) {
		$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
			$crypto_algo, $hash_algo);
		$this->assertInstanceOf($expected_class, $algo);
	}
	
	public function provideAlgoForAsymmetricCrypto() {
		$rsa = new RSAEncryptionAlgorithmIdentifier();
		$ec = new ECPublicKeyAlgorithmIdentifier(
			ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
		$md5 = new MD5AlgorithmIdentifier();
		$sha1 = new SHA1AlgorithmIdentifier();
		$sha224 = new SHA224AlgorithmIdentifier();
		$sha256 = new SHA256AlgorithmIdentifier();
		$sha384 = new SHA384AlgorithmIdentifier();
		$sha512 = new SHA512AlgorithmIdentifier();
		return array(
			/* @formatter:off */
			[$rsa, $md5, MD5WithRSAEncryptionAlgorithmIdentifier::class],
			[$rsa, $sha1, SHA1WithRSAEncryptionAlgorithmIdentifier::class],
			[$rsa, $sha224, SHA224WithRSAEncryptionAlgorithmIdentifier::class],
			[$rsa, $sha256, SHA256WithRSAEncryptionAlgorithmIdentifier::class],
			[$rsa, $sha384, SHA384WithRSAEncryptionAlgorithmIdentifier::class],
			[$rsa, $sha512, SHA512WithRSAEncryptionAlgorithmIdentifier::class],
			[$ec, $sha1, ECDSAWithSHA1AlgorithmIdentifier::class],
			[$ec, $sha224, ECDSAWithSHA224AlgorithmIdentifier::class],
			[$ec, $sha256, ECDSAWithSHA256AlgorithmIdentifier::class],
			[$ec, $sha384, ECDSAWithSHA384AlgorithmIdentifier::class],
			[$ec, $sha512, ECDSAWithSHA512AlgorithmIdentifier::class]
			/* @formatter:on */
		);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidCryptoAlgo() {
		$crypto_algo = new SignatureFactoryTest_InvalidCryptoAlgo();
		$hash_algo = new MD5AlgorithmIdentifier();
		SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
			$crypto_algo, $hash_algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidRSAHashAlgo() {
		$crypto_algo = new RSAEncryptionAlgorithmIdentifier();
		$hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
		SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
			$crypto_algo, $hash_algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidECHashAlgo() {
		$crypto_algo = new ECPublicKeyAlgorithmIdentifier(
			ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
		$hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
		SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
			$crypto_algo, $hash_algo);
	}
}


class SignatureFactoryTest_InvalidCryptoAlgo extends SpecificAlgorithmIdentifier implements 
	AsymmetricCryptoAlgorithmIdentifier
{
	public function name() {
		return "test";
	}
	
	protected function _paramsASN1() {
		return null;
	}
}


class SignatureFactoryTest_InvalidHashAlgo extends SpecificAlgorithmIdentifier implements 
	HashAlgorithmIdentifier
{
	public function name() {
		return "test";
	}
	
	protected function _paramsASN1() {
		return null;
	}
}
