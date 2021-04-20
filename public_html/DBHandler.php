<?php
class DBHandler
{
	private $hostname, $database, $username, $password;
	private $conn;
	private static $instance = null;

    private function __construct() 
	{
		$this->hostname = "localhost";
		$this->database = "ipv6alizer";
		$this->username = "ipv6alizer";
		$this->password = "supersecretpassword";
	}

	private function __destruct() 
	{
		$this->conn = null;
	}

	private function connect() {
		if($this->conn === null) {
			$this->conn = new PDO("mysql:host=".$this->hostname.";dbname=".$this->database, $this->username, $this->password);
			$this->conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
			$this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		}
	}

	private function closeConnection() {
		$this->conn = null;
	}

	private function queryStoredProcedure($sp, array $params = array()) {
		$this->connect();
		$query = "CALL ".$sp."(";
		foreach($params as $key => $value) {
			$query.=":".$key.",";
		}
		$query = rtrim($query, ",");
		$query.=")";
		$statement = $this->conn->prepare($query);
		foreach($params as $key => $value) {
			$statement->bindValue(":".$key, $value);
		}
		$statement->execute();
		$result = $statement->fetchAll(PDO::FETCH_ASSOC);
		$this->closeConnection();
		return $result;
	}

	private function executeStoredProcedure($sp, array $params = array()) {
		$this->connect();
		$query = "CALL ".$sp."(";
		foreach($params as $key => $value) {
			$query.=":".$key.",";
		}
		$query = rtrim($query, ",");
		$query.=")";

		$statement = $this->conn->prepare($query);
		foreach($params as $key => $value) {
			$statement->bindValue(":".$key, $value);
		}
		$statement->execute();
		$this->closeConnection();
	}

	public static function &getInstance()
	{
		if(self::$instance === null) {
			self::$instance = new DBHandler();
		}
		return self::$instance;
	}
 	

	public function GetDomainLastCheckDateTime($name) {
		$result = $this->queryStoredProcedure("getDomainLastCheck", array("name" => $name));
		return $result[0]["lastRun"];
	}

	public function SaveDomainResult($name, $address, array $rows) {
		$delimitedString = "";
		foreach($rows as $row) {
			$delimitedString.=$row."|";
		}
		$delimitedString = rtrim($delimitedString, "|");
		$delim = "|";
		$this->executeStoredProcedure("saveDomainResult", array("name" => $name, "address" => $address, "data" => $delimitedString, "delim" => $delim));
	}

	public function GetDomainResult($name) {
		$result = $this->queryStoredProcedure("getDomainResult", array("name" => $name));
		$infoArray = array();
		foreach($result as $row) {
		    $infoArray[] = new Info($row["dName"], $row["dAddress"], $row["iResult"], $row["iInsDat"]);
		}
		return $infoArray;
	}

	public function GetHostIp() {
		$result = $this->queryStoredProcedure("getHostIp");
		return $result[0]["ip"];
	}
	public function getLastTweet($domain) {
		$result = $this->queryStoredProcedure("getLastTweet", array("domain" => $domain));
		$lastTweet = date("Y-m-d H:i:s", strtotime("1970-01-01"));
		if (is_array($result) && count($result) > 0) { 
			$lastTweet = $result[count($result) - 1]["lastTweet"];
		}
		return $lastTweet;
	}
	public function saveTweet($domain, $tweet, $protocol) {
		$this->executeStoredProcedure("saveTweet", array("domain" => $domain, "tweet" => $tweet, "protocol" => $protocol));
	}
}

