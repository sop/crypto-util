<?php

namespace CryptoUtil\PBE;

use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\HashFunc\MD5;
use CryptoUtil\PBE\HashFunc\SHA1;
use CryptoUtil\PBE\PBEKD\PBEKDF;
use CryptoUtil\PBE\PRF\PRF;


/**
 * Base class for password-based encryption schemes.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6
 */
abstract class PBEScheme
{
	/**
	 * Encrypt data.
	 *
	 * @param string $data Plaintext
	 * @param string $password Password
	 * @return string Ciphertext
	 */
	abstract public function encrypt($data, $password);
	
	/**
	 * Encrypt data with pre-derived key.
	 *
	 * @param string $data Plaintext
	 * @param string $key Derived key
	 * @return string Ciphertext
	 */
	abstract public function encryptWithKey($data, $key);
	
	/**
	 * Decrypt data.
	 *
	 * @param string $data Ciphertext
	 * @param string $password Password
	 * @return string Plaintext
	 */
	abstract public function decrypt($data, $password);
	
	/**
	 * Decrypt data with pre-derived key.
	 *
	 * @param string $data Ciphertext
	 * @param string $key Derived key
	 * @return string Plaintext
	 */
	abstract public function decryptWithKey($data, $key);
	
	/**
	 * Get key-derivation function.
	 *
	 * @return PBEKDF
	 */
	abstract public function kdf();
	
	/**
	 * Add padding.
	 *
	 * @param string $data Data to pad
	 * @param int $blocksize Block size of the underlying cipher
	 * @return string
	 */
	protected function _addPadding($data, $blocksize) {
		$padding = $blocksize - strlen($data) % $blocksize;
		$data .= str_repeat(chr($padding), $padding);
		return $data;
	}
	
	/**
	 * Remove padding.
	 *
	 * It's important that exceptions thrown here are no propagated to any
	 * user interface. Doing so would expose ciphertext to the padding oracle
	 * attack.
	 *
	 * @param string $data Padded data
	 * @param int $blocksize Block size of the underlying cipher
	 * @throws \UnexpectedValueException If the padding is invalid
	 * @return string
	 */
	protected function _removePadding($data, $blocksize) {
		$len = strlen($data);
		if (!$len) {
			throw new \UnexpectedValueException("No padding.");
		}
		$padding = ord($data[$len - 1]);
		if ($len < $padding || $padding > $blocksize) {
			throw new \UnexpectedValueException("Invalid padding length.");
		}
		$ps = substr($data, -$padding);
		if ($ps !== str_repeat(chr($padding), $padding)) {
			throw new \UnexpectedValueException("Invalid padding string.");
		}
		return substr($data, 0, -$padding);
	}
	
	/**
	 * Get PBEScheme by algorithm identifier.
	 *
	 * @param PBEAlgorithmIdentifier $algo
	 * @param Crypto $crypto
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromAlgorithmIdentifier(PBEAlgorithmIdentifier $algo, 
			Crypto $crypto) {
		if ($algo->oid() == AlgorithmIdentifier::OID_PBES2) {
			if (!$algo instanceof PBES2AlgorithmIdentifier) {
				throw new \UnexpectedValueException("Not a PBES2 algorithm.");
			}
			$prf = PRF::fromAlgorithmIdentifier(
				$algo->kdfAlgorithmIdentifier()->prfAlgorithmIdentifier());
			return new PBES2($prf, $algo->esAlgorithmIdentifier(), $algo->salt(), 
				$algo->iterationCount(), $crypto);
		}
		switch ($algo->oid()) {
		case AlgorithmIdentifier::OID_PBE_WITH_MD5_AND_DES_CBC:
			return new PBES1(new MD5(), new DESCBCAlgorithmIdentifier(), 
				$algo->salt(), $algo->iterationCount(), $crypto);
		case AlgorithmIdentifier::OID_PBE_WITH_MD5_AND_RC2_CBC:
			return new PBES1(new MD5(), new RC2CBCAlgorithmIdentifier(), 
				$algo->salt(), $algo->iterationCount(), $crypto);
		case AlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_DES_CBC:
			return new PBES1(new SHA1(), new DESCBCAlgorithmIdentifier(), 
				$algo->salt(), $algo->iterationCount(), $crypto);
		case AlgorithmIdentifier::OID_PBE_WITH_SHA1_AND_RC2_CBC:
			return new PBES1(new SHA1(), new RC2CBCAlgorithmIdentifier(), 
				$algo->salt(), $algo->iterationCount(), $crypto);
		}
		throw new \UnexpectedValueException(
			"No encryption scheme for oid " . $algo->oid() . ".");
	}
}
