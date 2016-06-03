<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndDESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithMD5AndRC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndDESCBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PBE\HashFunc\MD5;
use CryptoUtil\PBE\PBES1;
use CryptoUtil\PBE\PBEScheme;


/**
 * @group pbe
 */
class PBESchemeTest extends PHPUnit_Framework_TestCase
{
	private static $_pbes;
	
	private static $_methods;
	
	public static function setUpBeforeClass() {
		self::$_pbes = new PBES1(new MD5(), new DESCBCAlgorithmIdentifier(), 
			"12345678", 8, Crypto::getDefault());
		// populate reflected methods
		self::$_methods = array();
		$pbes_refl = new ReflectionClass(self::$_pbes);
		foreach ($pbes_refl->getMethods(ReflectionMethod::IS_PROTECTED) as $mtd) {
			$name = $mtd->getName();
			$mtd->setAccessible(true);
			self::$_methods[$name] = $mtd;
		}
	}
	
	public static function tearDownAfterClass() {
		self::$_pbes = null;
		self::$_methods = null;
	}
	
	public function testAddPadding() {
		$str = self::$_methods["_addPadding"]->invoke(self::$_pbes, "test", 8);
		$this->assertEquals("test\x4\x4\x4\x4", $str);
		return $str;
	}
	
	/**
	 * @depends testAddPadding
	 *
	 * @param string $str
	 */
	public function testRemovePadding($str) {
		$result = self::$_methods["_removePadding"]->invoke(self::$_pbes, $str, 
			8);
		$this->assertEquals("test", $result);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testNoPadding() {
		self::$_methods["_removePadding"]->invoke(self::$_pbes, "", 8);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testPaddingTooLong() {
		self::$_methods["_removePadding"]->invoke(self::$_pbes, 
			hex2bin("badcafeeffffffff"), 16);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testPaddingLargerThanBlock() {
		self::$_methods["_removePadding"]->invoke(self::$_pbes, 
			"testtes" . str_repeat("\x9", 9), 8);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPadding() {
		self::$_methods["_removePadding"]->invoke(self::$_pbes, 
			hex2bin("badcafeeffffff04"), 8);
	}
	
	/**
	 * @dataProvider provideFromAlgo
	 *
	 * @param PBEAlgorithmIdentifier $algo
	 */
	public function testFromAlgo(PBEAlgorithmIdentifier $algo) {
		$pbe = PBEScheme::fromAlgorithmIdentifier($algo, Crypto::getDefault());
		$this->assertInstanceOf(PBEScheme::class, $pbe);
	}
	
	public function provideFromAlgo() {
		static $salt = "12345678";
		static $iteration_count = 8;
		return array(
			/* @formatter:off */
			[new PBEWithMD5AndDESCBCAlgorithmIdentifier($salt, $iteration_count)],
			[new PBEWithMD5AndRC2CBCAlgorithmIdentifier($salt, $iteration_count)],
			[new PBEWithSHA1AndDESCBCAlgorithmIdentifier($salt, $iteration_count)],
			[new PBEWithSHA1AndRC2CBCAlgorithmIdentifier($salt, $iteration_count)],
			[new PBES2AlgorithmIdentifier(
				new PBKDF2AlgorithmIdentifier($salt, $iteration_count),
				new DESCBCAlgorithmIdentifier())]
			/* @formatter:on */
		);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedAlgo() {
		PBEScheme::fromAlgorithmIdentifier(
			new PBESchemeTest_UnsupportedPBEAlgo("12345678", 8), 
			Crypto::getDefault());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidPBES2AlgoFail() {
		PBEScheme::fromAlgorithmIdentifier(
			new PBESchemeTest_InvalidPBES2Algo("12345678", 8), 
			Crypto::getDefault());
	}
}


class PBESchemeTest_UnsupportedPBEAlgo extends PBEAlgorithmIdentifier
{
	public function __construct($salt, $iteration_count) {
		parent::__construct($salt, $iteration_count);
		$this->_oid = "1.3.6.1.3";
	}
	
	protected function _paramsASN1() {
		return null;
	}
}


class PBESchemeTest_InvalidPBES2Algo extends PBEAlgorithmIdentifier
{
	public function __construct($salt, $iteration_count) {
		parent::__construct($salt, $iteration_count);
		$this->_oid = AlgorithmIdentifier::OID_PBES2;
	}
	
	protected function _paramsASN1() {
		return null;
	}
}