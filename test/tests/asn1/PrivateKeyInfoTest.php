<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * @group asn1
 */
class PrivateKeyInfoTest extends PHPUnit_Framework_TestCase
{
	public function testDecode() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$pki = PrivateKeyInfo::fromDER($pem->data());
		$this->assertInstanceOf(PrivateKeyInfo::class, $pki);
		return $pki;
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param PrivateKeyInfo $pki
	 */
	public function testAlgoOID(PrivateKeyInfo $pki) {
		$this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, 
			$pki->algorithmIdentifier()
				->oid());
	}
}
