<?php

namespace CryptoUtil\Crypto;

use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;


/**
 * Base class for crypto engine implementations.
 */
abstract class Crypto
{
	/**
	 * Sign data with given algorithm using given private key.
	 *
	 * @param string $data Data to sign
	 * @param PrivateKeyInfo $privkey_info Private key
	 * @param SignatureAlgorithmIdentifier $algo Signature algorithm
	 * @return Signature
	 */
	abstract public function sign($data, PrivateKeyInfo $privkey_info, 
			SignatureAlgorithmIdentifier $algo);
	
	/**
	 * Verify signature with given algorithm using given public key.
	 *
	 * @param string $data Data to verify
	 * @param Signature $signature Signature
	 * @param PublicKeyInfo $pubkey_info Public key
	 * @param SignatureAlgorithmIdentifier $algo Signature algorithm
	 * @return bool True if signature matches
	 */
	abstract public function verify($data, Signature $signature, 
			PublicKeyInfo $pubkey_info, SignatureAlgorithmIdentifier $algo);
	
	/**
	 * Encrypt data with given algorithm using given key.
	 *
	 * Padding must be added by the caller. Initialization vector is
	 * taken from the algorithm identifier if available.
	 *
	 * @param string $data Plaintext
	 * @param string $key Encryption key
	 * @param CipherAlgorithmIdentifier $algo Encryption algorithm
	 * @return string Ciphertext
	 */
	abstract public function encrypt($data, $key, 
			CipherAlgorithmIdentifier $algo);
	
	/**
	 * Decrypt data with given algorithm using given key.
	 *
	 * Possible padding is not removed and must be handled by the caller.
	 * Initialization vector is taken from the algorithm identifier if
	 * available.
	 *
	 * @param string $data Ciphertext
	 * @param string $key Encryption key
	 * @param CipherAlgorithmIdentifier $algo Encryption algorithm
	 * @return string Plaintext
	 */
	abstract public function decrypt($data, $key, 
			CipherAlgorithmIdentifier $algo);
	
	/**
	 * Get default supported crypto implementation.
	 *
	 * @return self
	 */
	public static function getDefault() {
		if (defined("OPENSSL_VERSION_NUMBER")) {
			return new OpenSSLCrypto();
		}
		throw new \RuntimeException("No crypto engine available");
	}
}
