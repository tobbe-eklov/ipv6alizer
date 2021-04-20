DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` FUNCTION `stringSplit`(
  str VARCHAR(16000),
  delim VARCHAR(12),
  pos INT
) RETURNS varchar(16000) CHARSET utf8
RETURN REPLACE(SUBSTRING(SUBSTRING_INDEX(str, delim, pos),
       LENGTH(SUBSTRING_INDEX(str, delim, pos -1)) + 1),
       delim, '')$$
DELIMITER ;
