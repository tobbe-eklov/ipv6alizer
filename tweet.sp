DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `saveTweet`(domain varchar(255), tweet varchar(400), protocol varchar(10))
BEGIN

	DECLARE selectedDomainId INT;
   SET selectedDomainId = (
       SELECT MAX(dId) FROM domains WHERE dName = domain
   );

   IF selectedDomainId > 0 THEN
		INSERT INTO tweets (
			tDomainId,
			tTweet,
			tProtocol,
			tInsDat
		) VALUES (
			selectedDomainId,
			tweet,
           protocol,
			NOW()
		);
   END IF;
END$$
DELIMITER ;
