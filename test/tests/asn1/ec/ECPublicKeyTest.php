<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\EC\ECPublicKey;


/**
 * @group asn1
 * @group ec
 */
class ECPublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
		$pk = ECPublicKey::fromPEM($pem);
		$this->assertInstanceOf(ECPublicKey::class, $pk);
		return $pk;
	}
}
