<?php

namespace CryptoUtil\PEM;


/**
 * Container for multiple PEM objects.
 */
class PEMBundle implements \Countable, \IteratorAggregate
{
	/**
	 * Array of PEM objects.
	 *
	 * @var PEM[] $_pems
	 */
	protected $_pems;
	
	/**
	 * Constructor
	 *
	 * @param PEM ...$pems
	 */
	public function __construct(PEM ...$pems) {
		$this->_pems = $pems;
	}
	
	/**
	 * Initialize from a string.
	 *
	 * @param string $str
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromString($str) {
		if (!preg_match_all(PEM::PEM_REGEX, $str, $matches, PREG_SET_ORDER)) {
			throw new \UnexpectedValueException("No PEM blocks.");
		}
		$pems = array_map(
			function ($match) {
				$payload = preg_replace('/\s+/', "", $match[2]);
				$data = base64_decode($payload, true);
				if (false === $data) {
					throw new \UnexpectedValueException(
						"Failed to decode PEM data.");
				}
				return new PEM($match[1], $data);
			}, $matches);
		return new self(...$pems);
	}
	
	/**
	 * Initialize from a file.
	 *
	 * @param string $filename
	 * @throws \RuntimeException If file reading fails
	 * @return self
	 */
	public static function fromFile($filename) {
		if (!is_readable($filename)) {
			throw new \RuntimeException("$filename is not readable.");
		}
		$str = file_get_contents($filename);
		if ($str === false) {
			/* Cannot be covered by tests */
			// @codeCoverageIgnoreStart
			throw new \RuntimeException("Failed to read $filename.");
			// @codeCoverageIgnoreEnd
		}
		return self::fromString($str);
	}
	
	/**
	 * Get all PEMs in a bundle.
	 *
	 * @return PEM[]
	 */
	public function all() {
		return $this->_pems;
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_pems);
	}
	
	/**
	 * Get iterator for PEMs.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_pems);
	}
}
