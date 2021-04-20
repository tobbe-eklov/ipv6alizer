#!/usr/bin/env bash

for i in $(seq 100 199) ; do
        ip6tables -t mangle -A PREROUTING -d 2001:db8:1::$i -j NFQUEUE --queue-num 1280
        ip6tables -I INPUT -p tcp --sport 80 -d 2001:db8:1::$i  -j DROP
        ip6tables -I INPUT -p tcp --sport 443 -d 2001:db8:1::$i  -j DROP
done
