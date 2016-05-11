<?php

namespace CryptoUtil\PBE;

use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\HashFunc\HashFunc;
use CryptoUtil\PBE\PBEKD\PBEKDF1;


/**
 * Implements password-based encryption scheme #1.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6.1
 */
class PBES1 extends PBEScheme
{
	/**
	 * Hash functor.
	 *
	 * @var HashFunc $_hashFunc
	 */
	protected $_hashFunc;
	
	/**
	 * Cipher algorithm.
	 *
	 * @var CipherAlgorithmIdentifier $_cipher
	 */
	protected $_cipher;
	
	/**
	 * Salt.
	 *
	 * @var string $_salt
	 */
	protected $_salt;
	
	/**
	 * Iteration count.
	 *
	 * @var int $_iterationCount
	 */
	protected $_iterationCount;
	
	/**
	 * Crypto engine.
	 *
	 * @var Crypto $_crypto
	 */
	protected $_crypto;
	
	/**
	 * Constructor
	 *
	 * @param HashFunc $hash_func
	 * @param CipherAlgorithmIdentifier $cipher
	 * @param string $salt
	 * @param int $iteration_count
	 * @param Crypto $crypto
	 */
	public function __construct(HashFunc $hash_func, 
			CipherAlgorithmIdentifier $cipher, $salt, $iteration_count, 
			Crypto $crypto) {
		$this->_hashFunc = $hash_func;
		$this->_cipher = $cipher;
		$this->_salt = $salt;
		$this->_iterationCount = $iteration_count;
		$this->_crypto = $crypto;
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::encrypt()
	 * @return string
	 */
	public function encrypt($data, $password) {
		$key = $this->kdf()->derive($password, $this->_salt, 
			$this->_iterationCount, 16);
		return $this->encryptWithKey($data, $key);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::encryptWithKey()
	 * @return string
	 */
	public function encryptWithKey($data, $key) {
		if (strlen($key) !== 16) {
			throw new \UnexpectedValueException("Invalid key length.");
		}
		$algo = $this->_cipher->withInitializationVector(substr($key, 8, 8));
		$str = $this->_addPadding($data, 8);
		return $this->_crypto->encrypt($str, substr($key, 0, 8), $algo);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::decrypt()
	 * @return string
	 */
	public function decrypt($data, $password) {
		$key = $this->kdf()->derive($password, $this->_salt, 
			$this->_iterationCount, 16);
		return $this->decryptWithKey($data, $key);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::decryptWithKey()
	 * @return string
	 */
	public function decryptWithKey($data, $key) {
		if (strlen($key) !== 16) {
			throw new \UnexpectedValueException("Invalid key length.");
		}
		$algo = $this->_cipher->withInitializationVector(substr($key, 8, 8));
		$str = $this->_crypto->decrypt($data, substr($key, 0, 8), $algo);
		return $this->_removePadding($str, 8);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::kdf()
	 * @return PBEKDF1
	 */
	public function kdf() {
		return new PBEKDF1($this->_hashFunc);
	}
}
