<?php

namespace CryptoUtil\PEM;


class PEM
{
	const TYPE_CERTIFICATE = "CERTIFICATE";
	const TYPE_CERTIFICATE_REQUEST = "CERTIFICATE REQUEST";
	const TYPE_ATTRIBUTE_CERTIFICATE = "ATTRIBUTE CERTIFICATE";
	const TYPE_PRIVATE_KEY = "PRIVATE KEY";
	const TYPE_PUBLIC_KEY = "PUBLIC KEY";
	const TYPE_ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";
	const TYPE_RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
	const TYPE_RSA_PUBLIC_KEY = "RSA PUBLIC KEY";
	const TYPE_EC_PRIVATE_KEY = "EC PRIVATE KEY";
	
	/**
	 * Regular expression to match PEM block
	 *
	 * @var string
	 */
	const PEM_REGEX = /* @formatter:off */ '/' . 
		/* line start */ '(?:^|[\r\n])' .
		/* header */     '-----BEGIN (.+?)-----[\r\n]+' .
		/* payload */    '(.+?)' .
		/* trailer */    '[\r\n]+-----END \\1-----' .
	'/ms'; /* @formatter:on */
	
	/**
	 * Content type
	 *
	 * @var string $_type
	 */
	protected $_type;
	
	/**
	 * Payload
	 *
	 * @var string $_data
	 */
	protected $_data;
	
	/**
	 * Constructor
	 *
	 * @param string $type Content type
	 * @param string $data Payload
	 */
	public function __construct($type, $data) {
		$this->_type = $type;
		$this->_data = $data;
	}
	
	/**
	 * Initialize from PEM formatted string
	 *
	 * @param string $str
	 * @throws \InvalidArgumentException
	 * @return self
	 */
	public static function fromString($str) {
		if (!preg_match(self::PEM_REGEX, $str, $match)) {
			throw new \InvalidArgumentException("Not a PEM formatted string");
		}
		$payload = preg_replace('/\s+/', "", $match[2]);
		$data = base64_decode($payload, true);
		if ($data === false) {
			throw new \InvalidArgumentException("Failed to decode PEM data");
		}
		return new self($match[1], $data);
	}
	
	/**
	 * Initialize from file
	 *
	 * @param string $filename Path to file
	 * @throws \InvalidArgumentException
	 * @return self
	 */
	public static function fromFile($filename) {
		if (!is_readable($filename)) {
			throw new \InvalidArgumentException("$filename is not readable");
		}
		$str = file_get_contents($filename);
		if ($str === false) {
			throw new \InvalidArgumentException("Failed to read $filename");
		}
		return self::fromString($str);
	}
	
	/**
	 * Get content type
	 *
	 * @return string
	 */
	public function type() {
		return $this->_type;
	}
	
	/**
	 * Get payload
	 *
	 * @return string
	 */
	public function data() {
		return $this->_data;
	}
	
	/**
	 * Encode to PEM string
	 *
	 * @return string
	 */
	public function str() {
		return "-----BEGIN {$this->_type}-----\n" .
			 trim(chunk_split(base64_encode($this->_data), 64, "\n")) . "\n" .
			 "-----END {$this->_type}-----";
	}
	
	public function __toString() {
		return $this->str();
	}
}
