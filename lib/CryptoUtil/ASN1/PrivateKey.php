<?php

namespace CryptoUtil\ASN1;

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;


abstract class PrivateKey
{
	/**
	 * Get public key component of the asymmetric key pair.
	 *
	 * @return PublicKey
	 */
	abstract public function publicKey();
	
	/**
	 * Get DER encoding of the private key.
	 *
	 * @return string
	 */
	abstract public function toDER();
	
	/**
	 * Initialize private key from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		switch ($pem->type()) {
		case PEM::TYPE_RSA_PRIVATE_KEY:
			return RSAPrivateKey::fromPEM($pem);
		case PEM::TYPE_PRIVATE_KEY:
			return PrivateKeyInfo::fromPEM($pem)->privateKey();
		}
		throw new \UnexpectedValueException(
			"PEM type " . $pem->type() . " is not a valid private key.");
	}
}
