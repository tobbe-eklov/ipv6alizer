<?php
class Info {
	 public $message = '';
     public $domain = '';
     public $address = '';
     public $insDate  = null;
     public $type = '';
     function __construct($domain, $address, $message, $insDate) {
	    $this->domain = $domain;
	    $this->address = $address;
	    $this->message = $message;
	    $this->insDate = $insDate;
	    $this->type = $this->GetTypeFromMessage($message);
	}
	function GetTypeFromMessage($message) {
		if (strpos($message, "TX") !== false || strpos($message, "RX") !== false) {
    		return "LOG";
		}
		$pos = strpos($message, ":");
		if($pos !== false && $pos > 0) {
			$type = substr($message, 0, $pos);
			if(in_array(strtoupper($type), array('INFO', 'WARNING', 'ERROR', 'NOTICE', 'RESULT'))) {
				$type = strtoupper($type);
				return $type;
			}
		}
		return 'NOT_SET';
	}
}  
