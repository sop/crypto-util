<?php

namespace CryptoUtil\PBE\PBEKD;


/**
 * Base class for key derivation functions used in password-based cryptography.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-5
 */
abstract class PBEKDF
{
	/**
	 * Derive a key from the password.
	 *
	 * @param string $password Password
	 * @param string $salt Salt
	 * @param int $count Iteration count
	 * @param int $length Derived key length
	 * @return string Key with a size of $length
	 */
	abstract public function derive($password, $salt, $count, $length);
}
