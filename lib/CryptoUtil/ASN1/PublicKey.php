<?php

namespace CryptoUtil\ASN1;

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPublicKey;


abstract class PublicKey
{
	/**
	 * Get DER encoding of the public key.
	 *
	 * @return string
	 */
	abstract public function toDER();
	
	/**
	 * Initialize public key from PEM.
	 *
	 * @param PEM $pem
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		switch ($pem->type()) {
		case PEM::TYPE_RSA_PUBLIC_KEY:
			return RSAPublicKey::fromPEM($pem);
		case PEM::TYPE_PUBLIC_KEY:
			return PublicKeyInfo::fromPEM($pem)->publicKey();
		}
		throw new \UnexpectedValueException(
			"PEM type " . $pem->type() . " is not a valid public key");
	}
}
