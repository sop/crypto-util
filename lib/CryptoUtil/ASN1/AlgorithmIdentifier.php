<?php

namespace CryptoUtil\ASN1;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\ECPublicKeyAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use CryptoUtil\ASN1\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndDESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndRC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndDESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD2WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;


/**
 * Implements AlgorithmIdentifier ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-C
 * @link https://tools.ietf.org/html/rfc3447#appendix-C
 */
abstract class AlgorithmIdentifier implements AlgorithmIdentifierType
{
	// RSA encryption
	const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
	
	// RSA signature algorithms
	const OID_MD2_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.2";
	const OID_MD4_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.3";
	const OID_MD5_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.4";
	const OID_SHA1_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.5";
	const OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";
	const OID_SHA384_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.12";
	const OID_SHA512_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.13";
	
	// Elliptic Curve signature algorithms
	const OID_ECDSA_WITH_SHA1 = "1.2.840.10045.4.1";
	const OID_ECDSA_WITH_SHA224 = "1.2.840.10045.4.3.1";
	const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
	const OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
	const OID_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";
	
	// Elliptic Curve public key
	const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
	
	// Cipher algorithms
	const OID_DES_CBC = "1.3.14.3.2.7";
	const OID_RC2_CBC = "1.2.840.113549.3.2";
	const OID_DES_EDE3_CBC = "1.2.840.113549.3.7";
	
	// PKCS #5 algorithms
	const OID_PBE_WITH_MD2_AND_DES_CBC = "1.2.840.113549.1.5.1";
	const OID_PBE_WITH_MD5_AND_DES_CBC = "1.2.840.113549.1.5.3";
	const OID_PBE_WITH_MD2_AND_RC2_CBC = "1.2.840.113549.1.5.4";
	const OID_PBE_WITH_MD5_AND_RC2_CBC = "1.2.840.113549.1.5.6";
	const OID_PBE_WITH_MD5_AND_XOR = "1.2.840.113549.1.5.9";
	const OID_PBE_WITH_SHA1_AND_DES_CBC = "1.2.840.113549.1.5.10";
	const OID_PBE_WITH_SHA1_AND_RC2_CBC = "1.2.840.113549.1.5.11";
	const OID_PBKDF2 = "1.2.840.113549.1.5.12";
	const OID_PBES2 = "1.2.840.113549.1.5.13";
	const OID_PBMAC1 = "1.2.840.113549.1.5.14";
	const OID_HMAC_WITH_SHA1 = "1.2.840.113549.2.7";
	
	/**
	 * Mapping from OID to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_OID_TO_CLASS = array(
		/* @formatter:off */
		self::OID_RSA_ENCRYPTION => RSAEncryptionAlgorithmIdentifier::class,
		self::OID_EC_PUBLIC_KEY => ECPublicKeyAlgorithmIdentifier::class,
		self::OID_DES_CBC => DESCBCAlgorithmIdentifier::class,
		self::OID_DES_EDE3_CBC => DESEDE3CBCAlgorithmIdentifier::class,
		self::OID_RC2_CBC => RC2CBCAlgorithmIdentifier::class,
		self::OID_HMAC_WITH_SHA1 => HMACWithSHA1AlgorithmIdentifier::class,
		self::OID_MD2_WITH_RSA_ENCRYPTION => MD2WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_MD5_WITH_RSA_ENCRYPTION => MD5WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_SHA1_WITH_RSA_ENCRYPTION => SHA1WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_SHA256_WITH_RSA_ENCRYPTION => SHA256WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_SHA384_WITH_RSA_ENCRYPTION => SHA384WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_SHA512_WITH_RSA_ENCRYPTION => SHA512WithRSAEncryptionAlgorithmIdentifier::class,
		self::OID_ECDSA_WITH_SHA1 => ECDSAWithSHA1AlgorithmIdentifier::class,
		self::OID_ECDSA_WITH_SHA224 => ECDSAWithSHA224AlgorithmIdentifier::class,
		self::OID_ECDSA_WITH_SHA256 => ECDSAWithSHA256AlgorithmIdentifier::class,
		self::OID_ECDSA_WITH_SHA384 => ECDSAWithSHA384AlgorithmIdentifier::class,
		self::OID_ECDSA_WITH_SHA512 => ECDSAWithSHA512AlgorithmIdentifier::class,
		self::OID_PBE_WITH_MD5_AND_DES_CBC => PBEWithMD5AndDESCBCAlgorithmIdentifier::class,
		self::OID_PBE_WITH_MD5_AND_RC2_CBC => PBEWithMD5AndRC2CBCAlgorithmIdentifier::class,
		self::OID_PBE_WITH_SHA1_AND_DES_CBC => PBEWithSHA1AndDESCBCAlgorithmIdentifier::class,
		self::OID_PBE_WITH_SHA1_AND_RC2_CBC => PBEWithSHA1AndRC2CBCAlgorithmIdentifier::class,
		self::OID_PBKDF2 => PBKDF2AlgorithmIdentifier::class,
		self::OID_PBES2 => PBES2AlgorithmIdentifier::class
		/* @formatter:on */
	);
	
	/**
	 * Object identifier.
	 *
	 * @var string $_oid
	 */
	protected $_oid;
	
	/**
	 * Get algorithm identifier parameters as ASN.1.
	 *
	 * If type allows parameters to be omitted, return null.
	 *
	 * @return Element|null
	 */
	abstract protected function _paramsASN1();
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$oid = $seq->at(0, Element::TYPE_OBJECT_IDENTIFIER)->oid();
		$params = $seq->has(1) ? $seq->at(1) : null;
		// if algorithm identifier has a specific implementation
		if (array_key_exists($oid, self::MAP_OID_TO_CLASS)) {
			$cls = self::MAP_OID_TO_CLASS[$oid];
			return $cls::_fromASN1Params($params);
		}
		return new GenericAlgorithmIdentifier($oid, $params);
	}
	
	/**
	 * Get object identifier.
	 *
	 * @return string
	 */
	public function oid() {
		return $this->_oid;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array(new ObjectIdentifier($this->_oid));
		$params = $this->_paramsASN1();
		if (isset($params)) {
			$elements[] = $params;
		}
		return new Sequence(...$elements);
	}
}
