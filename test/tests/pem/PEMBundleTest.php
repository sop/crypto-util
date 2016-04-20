<?php

use CryptoUtil\PEM\PEMBundle;


/**
 * @group pem
 */
class PEMBundleTest extends PHPUnit_Framework_TestCase
{
	/**
	 *
	 * @return PEMBundle
	 */
	public function testBundle() {
		$bundle = PEMBundle::fromFile(TEST_ASSETS_DIR . "/bundle/cacert.pem");
		$this->assertInstanceOf(PEMBundle::class, $bundle);
		return $bundle;
	}
	
	/**
	 * @depends testBundle
	 *
	 * @param PEMBundle $bundle
	 */
	public function testCount(PEMBundle $bundle) {
		$this->assertCount(150, $bundle);
	}
}
