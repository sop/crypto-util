<?php

namespace CryptoUtil\ASN1;

use CryptoUtil\ASN1\EC\ECPrivateKey;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\PEM\PEM;


abstract class PrivateKey
{
	/**
	 * Get private key info for the private key.
	 *
	 * @return PrivateKeyInfo
	 */
	abstract public function privateKeyInfo();
	
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
			return RSAPrivateKey::fromDER($pem->data());
		case PEM::TYPE_EC_PRIVATE_KEY:
			return ECPrivateKey::fromDER($pem->data());
		case PEM::TYPE_PRIVATE_KEY:
			return PrivateKeyInfo::fromDER($pem->data())->privateKey();
		}
		throw new \UnexpectedValueException(
			"PEM type " . $pem->type() . " is not a valid private key.");
	}
}
