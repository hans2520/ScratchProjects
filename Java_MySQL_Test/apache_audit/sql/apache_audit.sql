START TRANSACTION;
DROP DATABASE IF EXISTS apache_audit;
CREATE DATABASE IF NOT EXISTS apache_audit DEFAULT CHARACTER SET = 'utf8' DEFAULT COLLATE 'utf8_general_ci';
USE apache_audit;

DROP TABLE IF EXISTS access_log, host_blacklist;

/*!50503 set default_storage_engine = InnoDB */;
/*!50503 select CONCAT('storage engine: ', @@default_storage_engine) as INFO */;

CREATE TABLE access_log (
	insert_id 	BIGINT(20) 		NOT NULL AUTO_INCREMENT PRIMARY KEY,
    log_date	DATETIME        NOT NULL,
    host_id		VARCHAR(255)    NOT NULL,
    request		VARCHAR(255)   	NOT NULL,
    response	SMALLINT		NOT NULL,    
    user_agent  VARCHAR(255)   	NOT NULL,
    UNIQUE KEY (log_date, host_id, request, response, user_agent),
    INDEX log_date_index (log_date),
    INDEX host_index (host_id(50)),
    INDEX request_index (request(255)),
    INDEX response_index (response) USING HASH,
    INDEX user_agent_index (user_agent(255))
);

CREATE TABLE host_blacklist (
	insert_id 	BIGINT(20) 		NOT NULL AUTO_INCREMENT PRIMARY KEY,
    host_id		VARCHAR(255)    NOT NULL UNIQUE,
    message		VARCHAR(255)   	NOT NULL,
    created		DATETIME        NOT NULL,
    updated		DATETIME,
    INDEX host_index (host_id(50))
);


flush /*!50503 binary */ logs;

COMMIT;

