# ipv6alizer
Code to create the old and now dead https://ipv6alizer.se who got to many false positives and I don't have time or money to support it longer. Please fork and make it better!

Files - Catalogs

scamper - The only scamper version I got to work, there are newer versions but I didn't got it to work. Install with ./configure etc

ip6tables.sh - since scamper is built for pf and not ip6tables we must do this trick. And an IPv6 addres is poisoned some time after it is used so I random the source addresses for the tests.

pmtu.sh - script to call scamper 

sudoers - scamper must run as root

public_html - the webb

ipv6alizer.sql - the mariadb/mysql database

Other .sp and .sql - some mariadb/mysql things

The twitter integration is using https://github.com/oysttyer/oysttyer 
