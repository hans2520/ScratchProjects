
LOAD DATA LOCAL INFILE 'C:/Users/Student/Documents/GitHub/hans2520/ScratchProjects/Java_MySQL_Test/Parser/src/test/resources/access.log' 
	INTO TABLE apache_audit.access_log FIELDS TERMINATED BY '|' LINES TERMINATED BY '\n'
	(log_date, host_id, request, response, user_agent);

SELECT * FROM apache_audit.access_log;
	
SELECT host_id, COUNT(host_id) FROM apache_audit.access_log WHERE log_date BETWEEN 
	'2017-01-01.13:00:00' AND DATE_ADD('2017-01-01.13:00:00', INTERVAL 1 HOUR) GROUP BY host_id HAVING COUNT(host_id) >= 5000;
	
INSERT INTO apache_audit.host_blacklist (host_id, message, created) VALUES ('192.168.164.209', 'Host traffic exceeded theshold traffic of 100', NOW())
	ON DUPLICATE KEY UPDATE updated = NOW();
	
INSERT INTO apache_audit.host_blacklist (host_id, message, created) VALUES ('192.168.164.209', 'Host traffic exceeded theshold hourly traffic of 100', NOW())
	ON DUPLICATE KEY UPDATE message = 'Host traffic exceeded daily theshold traffic of 250', updated = NOW();
	
SELECT * FROM apache_audit.host_blacklist;

