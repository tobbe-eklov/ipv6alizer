<?php
require_once("Info.php");
require_once("DBHandler.php");
require_once("Punycode.php");
use TrueBV\Punycode;
date_default_timezone_set('Europe/Amsterdam');

$action = sanitizeString($_REQUEST['action']);
if(isset($action)) {
	$action = strtolower($action);
	switch($action) {
		case "maximumtransmissionunittest":
		if(isset($_REQUEST['address']) && !empty($_REQUEST['address'])) {
			$address = $_REQUEST['address'];
			if (substr($address, 0, strlen("http://")) == "http://") {
				$address = substr($address, strlen("http://"));
			} 
			else if (substr($address, 0, strlen("https://")) == "https://") {
				$address = substr($address, strlen("https://"));
			} 
			$address = encodeUri($address);
			$https = sanitizeString($_REQUEST['https']);
			$testResult = getResult($address, $https);
			$encodedResult = json_encode($testResult);
			echo $encodedResult;
		}
		else {
			$testResult = array("success" => false, "label" => "", "rows" => array(new Info("", "", "ERROR: No target specified.", date_default_timezone_get())));
			$encodedResult = json_encode($testResult);
			echo $encodedResult;
		}
		break;
		case "report":
		if(isset($_REQUEST['address'])) {
			$address = sanitizeString($_REQUEST['address']);
			$encodedUri = "";
			if (substr($address, 0, strlen("http://")) == "http://") {
				$encodedUri = encodeUri(substr($address, strlen("http://")));
				$address = "http://".$encodedUri;
			} 
			else if (substr($address, 0, strlen("https://")) == "https://") {
				$encodedUri = encodeUri(substr($address, strlen("https://")));
				$address = "https://".$encodedUri;
			}
			if(!isValidDomain($encodedUri)) {
				$testResult["success"] = false;
				$testResult["label"] = "";
				$testResult["rows"][] = new Info("", "", "ERROR: Invalid domain name.", date_default_timezone_get());
				$encodedResult = json_encode($testResult);
				echo $encodedResult;
			}
			else {
				$testResult = getLastResult($address);
				$encodedResult = json_encode($testResult);
				echo $encodedResult;
			}
		}
		else {
			$testResult = array("success" => false, "label" => "", "rows" => array(new Info("", "", "ERROR: No target specified.", date_default_timezone_get())));
			$encodedResult = json_encode($testResult);
			echo $encodedResult;
		}
		break;
		case "tweet":
		if(isset($_REQUEST['address'])) {
			$address = $_REQUEST['address'];//sanitizeString($_REQUEST['address']);
			$useHttps = sanitizeString($_REQUEST['https']);
			if (substr($address, 0, strlen("http://")) == "http://") {
				$address = substr($address, strlen("http://"));
			} 
			else if (substr($address, 0, strlen("https://")) == "https://") {
				$address = substr($address, strlen("https://"));
			} 
			$encodedUri = encodeUri($address);

			$testResult = getLastResult((($useHttps === "true") ? "https://" : "http://").$encodedUri);
			
			$tweetResult = tweetResult($testResult);
			$encodedResult = json_encode($tweetResult);				
		}
		else {
			$encodedResult = json_encode("Tweet address missing!");
		}
		echo $encodedResult;
		break;
		default:
		break;
	}
}

function getResult($name, $useHttps) {		
	$result = array("success" => true, "label" => "", "rows" => array());
	$remoteAddress = $_SERVER["REMOTE_ADDR"]; //Client IP
	if (filter_var($remoteAddress, FILTER_VALIDATE_IP) === false) {
		$remoteAddress = '';
	}
	if(!isValidDomain($name)) {
		$result["success"] = false;
		$result["rows"][] = new Info($name, $remoteAddress, "ERROR: Invalid domain name.", date_default_timezone_get());
		return $result;
	}
	$dbh = DBHandler::getInstance();
	$callingHostAddress = $dbh->getHostIp(); //Get rotated IP from database store
	$lastDateString = $dbh->getDomainLastCheckDateTime((($useHttps === "true") ? "https://" : "http://").$name);
	$now = strtotime(date("Y-m-d H:i:s"));
	$expire = strtotime("+3 minutes", strtotime($lastDateString));
	if (!filter_var($callingHostAddress, FILTER_VALIDATE_IP) === false) {
		if(date("Y-m-d H:i:s", $expire) < date("Y-m-d H:i:s", $now)) {
			//echo "Cached data expired. We need to refresh.";
			if(strpos($name, '/') !== false) {  
				$arr = explode("/", $name, 2);
				$domain = $arr[0];
			}
			else {
				$domain = $name;
			}

			$testResultData = executeTest($name, $domain, $callingHostAddress, ($useHttps === "true") ? "https" : "http");
			$dbh->saveDomainResult((($useHttps === "true") ? "https://" : "http://").$name, "", $testResultData);
		}
		else {
			$result["rows"][] = new Info($name, $remoteAddress, "NOTICE: $name was recently tested. Using stored result.", date_default_timezone_get());
		}
	}
	else {
		$result["rows"][] = new Info($name, $remoteAddress, "INFO: Unable to refresh. Using cached data.", date_default_timezone_get());
	}
	$storedResultData = $dbh->getDomainResult((($useHttps === "true") ? "https://" : "http://").$name);
	foreach($storedResultData as $storedResult) {
		$result["rows"][] = $storedResult;
		if(strpos($storedResult->message, 'result: ') !== false) {
			$resultStringParts = explode("result: ", $storedResult->message);
			if(count($resultStringParts) == 2) {
				$result["label"] = substr($resultStringParts[1], 0, strpos($resultStringParts[1], PHP_EOL));	
			}
		}
	}
	return $result;
}
function getTestResult($url, $name, $callingHostAddress, $protocol) {
	$result = array();
    $hostName = $name;
   
 	foreach (array("NOTICE: Test URL: ".$url, "ERROR: Test name: ".$name, "SYNC/ACK RX", "INFO: server-mss 0, result: pmtud-error test") as $row) {
    	//$result[] = trim($row).explode("\n", $row);
    	$result[] = trim($row);
 	}

 	return $result;
} 
//pmtu.sh www.regeringen.se 2001:db8:1::116 http ( eller https )
function executeTest($url, $name, $callingHostAddress, $protocol) {
	$cmd="/home/ipv6alizer/pmtu.sh ".escapeshellarg($url)." ".escapeshellarg($name)." ".escapeshellarg($callingHostAddress)." ".escapeshellarg($protocol);
	$result = array();
	try {
		while (@ ob_end_flush());
		$proc = popen($cmd, 'r');
	 	while (!feof($proc)) {
	 		$row = trim(fread($proc, 4096));
	 		if (isset($row) && strlen($row) > 0) {
	 	 		$result[] = $row;
	 	 	}
			@flush();
	  	}
  	}
  	catch(Exception $e) {
  		$result[] = $e->getMessage();
  	}
 	return $result;
}                                                                                                                                                                                                                                                                                         
function executeTweet($label, $domain) {
	$result = "";
	#$cmd = "tweet --consumer-key 4GwY031MY5CBuSzIlm1A7BpuQ --consumer-secret BgjrqPjIMKtd2fYb3fDMXGBmoOvsf3GRgvafIYNjNKfbWzOHAQ --access-secret "
	#."9oK4TTWMBCteitnb9DuSHYYeLgfcUe166Gw1CgkQVCW1I --access-key 796767075909988352-bfQDJHYsdwHfx6WcEyMfDJyRmODLsaQ \"".escapeshellarg($domain)." tested with result: ".escapeshellarg($label)." - ".escapeshellarg("http://ipv6alizer.se?address=".$domain)."\"";
	$cmd = "perl /home/ipv6alizer/oysttyer/oysttyer.pl -hold -status=\"".escapeshellarg($domain)." tested with result: ".escapeshellarg($label)." - ".escapeshellarg("http://ipv6alizer.se?address=".$domain)."\"";
	try {
		while (@ ob_end_flush());
		$proc = popen($cmd, 'r');
		while (!feof($proc)) {
		 	$row = trim(fread($proc, 4096));
		 	if (isset($row) && strlen($row) > 0) {
		 	 	$result = $row;
		 	}
			@flush();
		}
	}
	catch(Exception $e) {
		$result = $e->getMessage();
	}
	
	return $result;
}
function getLastResult($name) {
	$result = array("success" => true, "label" => "", "rows" => array());
	$dbh = DBHandler::getInstance();
	$storedResultData = $dbh->getDomainResult($name);
	foreach($storedResultData as $storedResult) {
		$result["rows"][] = $storedResult;
		if(strpos($storedResult->message, 'result: ') !== false) {
			$resultStringParts = explode("result: ", $storedResult->message);
			if(count($resultStringParts) == 2) {
				$result["label"] = substr($resultStringParts[1], 0, strpos($resultStringParts[1], PHP_EOL));
			}
		}
	}
	return $result;
}
function tweetResult($result) {
	if(!isset($result["label"]) || trim($result["label"])==='') {
		return "No result found!";
	}
	$domain = $result["rows"][0]->domain;
	if(substr($domain, 0, 7 ) === "http://") {
		$protocol = "http";
	}
	else if(substr($domain, 0, 8 ) === "https://") {
		$protocol = "https";
	}
	else {
		return "Unable to identify protocol!";
	}
	$lastTweet = getLastTweet($domain);
	$expire = strtotime("+30 minutes", strtotime($lastTweet));
	if(date("Y-m-d H:i:s", $expire) < date("Y-m-d H:i:s")) {
		$tweetResult = executeTweet($result["label"], $result["rows"][0]->domain);
		saveTweet($domain, $result["label"], $protocol);
	}
	else {
		$tweetResult = "Result for this domain was recently posted, let's wait a bit before posting it again.";
	}
	return $tweetResult;
}
function getLastTweet($domain) {
	$dbh = DBHandler::getInstance();
	$result = $dbh->getLastTweet($domain);
	return $result;
}
function saveTweet($domain, $tweet, $protocol) {
	$dbh = DBHandler::getInstance();
	$dbh->saveTweet($domain, $tweet, $protocol);
}
function sanitizeString($string) {
	$res = HtmlEncode(removeSemiColon(filter_var($string, FILTER_SANITIZE_STRING)));
	return $res;
}
function removeSemiColon($string) {
	$res = $string;
	if (strpos($res, ';') !== false) {
		if(strpos($res, ';') > 0) {
    		$res = substr($res, 0, strpos($res, ';'));
    	}
    	else {
    		$res = '';
    	}
	}
	return $res;
}
function encodeUri($uri) {
	if(!empty($uri)) {
		$punyCode = new Punycode();
		$res = HtmlEncode(removeSemiColon(filter_var($punyCode->Encode($uri), FILTER_SANITIZE_URL)));
		return $res;
	}
	return $uri;
}
function decodeUri($uri) {
	if(!empty($uri)) {
		$punyCode = new Punycode();
		$res = removeSemiColon(filter_var($punyCode->Decode($uri), FILTER_SANITIZE_URL));		
		return $res;
	}
	return $uri;
}
function htmlEncode($str) {
	$str = htmlentities(mb_convert_encoding($str, 'UTF-8', 'UTF-8'), ENT_QUOTES, 'UTF-8');
	return $str;
}
function isValidDomain($str)
{
    if(preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*(([\/]+[a-zA-Z0-9\-_]+)*\.[a-zA-Z0-9\-_]+)?$/i", $str) && preg_match("/^.{1,253}$/", $str) && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*(([\/]+[a-zA-Z0-9\-_]+)*\.[a-zA-Z0-9\-_]+)?$/", $str)) {
    	return true;
	}
	return false;
}
