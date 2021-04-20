DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `fillDefaultIps`()
BEGIN
    DECLARE i INT;
    DECLARE addresses NVARCHAR(4000);
        
    SET i = 100;    
    WHILE i <= 199 DO
        INSERT INTO hostipstore (
            hisIp,
            hisInsDat,
            hisUpdDat
            )
        SELECT
            CONCAT('2a07:1c80:100:193::', i),
            NOW(),
            NOW();
            
        SET i = i + 1;
    END WHILE;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `getDomainLastCheck`(name varchar(255))
BEGIN
    SELECT 
        MAX(iInsDat) AS lastRun
    FROM info INNER JOIN domains on iDomainId = dId
    WHERE dName = name
    LIMIT 1;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `getDomainResult`(name varchar(255))
BEGIN

    DECLARE selectedDomainId INT;
    SET selectedDomainId = (
        SELECT MAX(dId) FROM domains WHERE dName = name
    );
    
    SELECT
        iDomainId,
        dName,
        dAddress,
        iResult,
        iInsDat
    FROM info INNER JOIN domains ON iDomainId = dId
    WHERE iDomainId = selectedDomainId;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `getHostIp`()
BEGIN
    DECLARE selectedIp varchar(100);
    DECLARE selectedId INT;
        
    SET selectedId = ( SELECT hisId FROM hostipstore ORDER BY hisUpdDat ASC LIMIT 1);    
    SET selectedIp =  ( SELECT hisIp FROM hostipstore WHERE hisId = selectedId);
    
    IF selectedId > 0 THEN
        UPDATE hostipstore
            SET hisUpdDat = NOW()
        WHERE hisId = selectedId;
    END IF;
    
    SELECT selectedIp AS ip;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `getLastTweet`(domain varchar(100))
BEGIN
    DECLARE selectedDomainId INT;
    SET selectedDomainId = (
        SELECT MAX(dId) FROM domains WHERE dName = domain
    );
    

    SELECT IFNULL(tInsDat, STR_TO_DATE('%Y-%m-%d','1970-01-01')) AS lastTweet FROM tweets WHERE tDomainId = selectedDomainId;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `saveDomainResult`(name varchar(255), address varchar(40), data TEXT, delim char(1))
BEGIN
    DECLARE selectedDomainId, i INT;
    DECLARE fullStr TEXT;
    DECLARE tmpStr TEXT;
    DECLARE inserted INT;
        
    DROP TABLE IF EXISTS tmpResult;
    CREATE TEMPORARY TABLE IF NOT EXISTS tmpResult (tmpInfo TEXT);
    SET selectedDomainId = 0, i=0;
    SET fullStr = data;
    split_loop:LOOP
         SET i=i+1;
         SET tmpStr= (SELECT stringSplit(fullStr,delim,i));
         IF tmpStr='' THEN
            LEAVE split_loop;
         END IF;
         INSERT INTO tmpResult (tmpInfo) values (tmpStr);
    END LOOP split_loop;
    

    -- If name is already registered, extract Id and save the new result
    IF EXISTS(SELECT * FROM domains where dName = name) THEN
        SET selectedDomainID = (SELECT MAX(dId) FROM domains WHERE dName = name);
        
        DELETE FROM info WHERE iDomainId = selectedDomainId AND iId <>0;
        
        IF selectedDomainId > 0 THEN
            INSERT INTO info (
                iDomainId,
                iResult,
                iInsDat
            )
            SELECT
                selectedDomainId,
                tmpInfo,
                NOW()
            FROM tmpResult;
        END IF;
    -- Otherwise, register the new name, assign an id and save the info
    ELSE
            INSERT INTO domains (
                dName,
                dAddress,
                dInsDat
            ) 
            VALUES (
                name,
                address,
                NOW()
            );
            SET selectedDomainID = (SELECT LAST_INSERT_ID());
            INSERT INTO info (
                iDomainId,
                iResult,
                iInsDat
            )
            SELECT
                selectedDomainId,
                tmpInfo,
                NOW()
            FROM tmpResult;
    END IF;
END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`ipv6alizer`@`localhost` PROCEDURE `hostIpSave`(addresses varchar(4000), delim char(1))
BEGIN
    DECLARE fullStr VARCHAR(4000);
    DECLARE tmpStr VARCHAR(100);
    DECLARE i INT;
    SET i = 0;

    DROP TABLE IF EXISTS tmpIps;
    CREATE TEMPORARY TABLE tmpIps(tmpIp varchar(40));
    
    SET fullStr = addresses;
    split_loop:LOOP
         SET i=i+1;
         SET tmpStr= (SELECT stringSplit(fullStr,delim,i));
         IF tmpStr='' THEN
            LEAVE split_loop;
         END IF;
         INSERT INTO tmpIps (tmpIp) values (tmpStr);
    END LOOP split_loop;
    
    INSERT INTO hostipstore (
        hisIp,
        hisInsDat,
        hisUpdDat
    )
    SELECT
        tmpIp,
        NOW(),
        NOW()
    FROM tmpIps WHERE tmpIp NOT IN (
        SELECT hisIp FROM hostipstore
    );
    
END$$
DELIMITER ;

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
