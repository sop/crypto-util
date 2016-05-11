<?php

use CryptoUtil\PEM\PEM;
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
	public function testAll(PEMBundle $bundle) {
		$this->assertContainsOnlyInstancesOf(PEM::class, $bundle->all());
	}
	
	/**
	 * @depends testBundle
	 *
	 * @param PEMBundle $bundle
	 */
	public function testCount(PEMBundle $bundle) {
		$this->assertCount(150, $bundle);
	}
	
	/**
	 * @depends testBundle
	 *
	 * @param PEMBundle $bundle
	 */
	public function testIterator(PEMBundle $bundle) {
		$values = array();
		foreach ($bundle as $pem) {
			$values[] = $pem;
		}
		$this->assertContainsOnlyInstancesOf(PEM::class, $values);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEM() {
		PEMBundle::fromString("nope");
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPEMData() {
		$str = <<<DATA
-----BEGIN TEST-----
%%%
-----END TEST-----
DATA;
		PEMBundle::fromString($str);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testInvalidFile() {
		PEMBundle::fromFile(TEST_ASSETS_DIR . "/nonexistent");
	}
}
