<?php

namespace CryptoUtil\PBE;

use CryptoUtil\ASN1\AlgorithmIdentifier\Feature\BlockCipherAlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\PBEKD\PBEKDF2;
use CryptoUtil\PBE\PRF\PRF;


/**
 * Implements password-based encryption scheme #2.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6.2
 */
class PBES2 extends PBEScheme
{
	/**
	 * Pseudorandom functor.
	 *
	 * @var PRF $_prf
	 */
	protected $_prf;
	
	/**
	 * Cipher algorithm.
	 *
	 * @var BlockCipherAlgorithmIdentifier $_cipher
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
	 * @param PRF $prf Pseudorandom functor
	 * @param BlockCipherAlgorithmIdentifier $cipher Algorithm
	 * @param string $salt Salt
	 * @param int $iteration_count Iteration count
	 * @param Crypto $crypto
	 */
	public function __construct(PRF $prf, BlockCipherAlgorithmIdentifier $cipher, 
			$salt, $iteration_count, Crypto $crypto) {
		$this->_prf = $prf;
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
			$this->_iterationCount, $this->_cipher->keySize());
		return $this->encryptWithKey($data, $key);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::encryptWithKey()
	 * @return string
	 */
	public function encryptWithKey($data, $key) {
		$str = $this->_addPadding($data, $this->_cipher->blockSize());
		return $this->_crypto->encrypt($str, $key, $this->_cipher);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::decrypt()
	 * @return string
	 */
	public function decrypt($data, $password) {
		$key = $this->kdf()->derive($password, $this->_salt, 
			$this->_iterationCount, $this->_cipher->keySize());
		return $this->decryptWithKey($data, $key);
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::decryptWithKey()
	 * @return string
	 */
	public function decryptWithKey($data, $key) {
		$str = $this->_crypto->decrypt($data, $key, $this->_cipher);
		return $this->_removePadding($str, $this->_cipher->blockSize());
	}
	
	/**
	 *
	 * @see \CryptoUtil\PBE\PBEScheme::kdf()
	 * @return PBEKDF2
	 */
	public function kdf() {
		return new PBEKDF2($this->_prf);
	}
}
