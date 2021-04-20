#!/usr/bin/env bash
# usage: pmtu.sh interlan.se interlan.se 2001:db8:100:193::1145 https

# Start here!

if [ -z "${1}" ] ; then
        echo "ERROR: $0 sitename"
        exit 10
fi

uri=${1}
domain=${2}
srcaddr=${3}
http=${4}


echo "INFO: Looking for AAAA RR at $domain...."
ipv6=$(dig -taaaa +short $domain| grep :)
#sleep 0.5


# Check if IPv6 exist
if [ ! "${ipv6}" ] ; then
                echo "ERROR: $domain dont have IPv6"
		echo "INFO: Please contact webbmaster for $domain to enable IPv6 support"
		echo "INFO: Test ended $(date)"
		exit
fi
if [ "${ipv6}" = "2001:db8:1::10" ] ; then
	echo "INFO: This host is located on same server as ipv6alizer.se and can't be tested"
	echo "INFO: We need more servers  - sorry..."
	echo "INFO: Test ended $(date)"
	exit
fi


echo "INFO: test started `date`"

curl -6 -s -q -m3 "${4}://${domain}" >/dev/null
exit="${?}"
        case "${exit}" in
        0|1)
		#echo "INFO: has functional IPv6" ;;
		;;
        7|28)
		echo "ERROR: can't connect over IPv6"
		echo "INFO: Test ended $(date)" 
		exit ;;
	60)
		echo "ERROR: Certifikate error"
		echo "INFO: Test ended $(date)"
		exit ;;

        *)
		echo "ERROR: can't connect over IPv6"
                echo "INFO: Test ended $(date)" 
		exit ;;
	esac

number=$(echo $ipv6|wc -w)
testaddress=$(echo $ipv6 | awk '{ print $1 }')

echo "INFO: $domain have $number ipv6 address{es}"
if [ "${number}" -gt "1"  ] ; then
	#echo "INFO: If all addresses is behind same loadbalancer the second test is probably unreliable"
	echo "INFO: we only test $testaddress "
fi

echo

	echo "INFO: testing $testsite at $i `date`"

	end=$(shuf -i100-199 -n1)

        echo "INFO: running scamper  -I \"tbit -M 1280 -t pmtud -S 2001:db8:102:193:100::${end} -u $http://$uri $testaddress\"" 
	sudo scamper  -I "tbit -M 1280 -t pmtud -S 2001:db8:1::${end} -u $http://$uri $testaddress" >>/tmp/scamper.$$
	result=`grep "result:" /tmp/scamper.$$`


        echo "INFO: ${result}"
        if [ "`echo ${result} | grep toosmall)"  ]; then
                echo "WARNING: $4://$domain payload to small for test"
		echo "INFO: Probably a redirect, try to enable https and/or add/remove www."
        fi
        if [ "$(echo ${result} | grep success)"  ]; then
                echo "NOTICE: $4://$domain is responding to PTB correctly"
        fi
        if [ "$(echo ${result} | grep nodata)"  ]; then
                 echo "ERROR: $4://$domain didn't test correct, try again in 30 minutes"
        fi
        if [ "$(echo ${result} | grep pmtud-fail)"  ]; then
                 echo "ERROR: $4://$domain don't listen to PTB "
        fi
        if [ "$(echo ${result} | grep tcp-noconn)"  ]; then
                 echo "ERROR: $4://$domain is broken and don't listen to IPv6 for $http://$uri"
        fi
        if [ "$(echo ${result} | grep tcp-rst)"  ]; then
                 echo "ERROR: $domain is broken and send's TCP RST for $http://$uri"
        fi

	cat /tmp/scamper.$$
	if [ -f "/tmp/scamper.$$" ] ; then
		rm /tmp/scamper.$$
	fi

echo "INFO: test ended $(date)"


