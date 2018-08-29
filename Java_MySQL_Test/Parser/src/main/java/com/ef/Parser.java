/**
 *
 * Parser takes "accesslog", "startDate", "duration" and "threshold" as command line arguments.
 * 		"accesslog" is the static log file, presented as "/path/to/file"
 * 		"startDate" is of "yyyy-MM-dd.HH:mm:ss" format, 
 * 		"duration" can take only "hourly", "daily" as inputs 
 * 		and 
 * 		"threshold" can be an integer.
 * 
 * Usage: 
 * 	 --accesslog="</path/to/file>" --startDate="<yyyy-MM-dd.HH:mm:ss>" --duration="<period>" --threshold=<integer>
 * 
 * Examples:
 * 
 *  java -cp "parser.jar" com.ef.Parser --accesslog=access.log --startDate=2017-01-01.13:00:00 --duration=hourly --threshold=100
 *	
 *	   -> Parser will find any IPs that made more than 100 requests starting from 2017-01-01.13:00:00 to 2017-01-01.14:00:00 
 *	      (one hour) and print them to console AND also load them to apache_audit.blocked_hosts with comments on why it's blocked.
 *
 *	java -cp "parser.jar" com.ef.Parser --accesslog=access.log --startDate=2017-01-01.13:00:00 --duration=daily --threshold=250
 *
 *	   -> Parser will find any IPs that made more than 250 requests starting from 2017-01-01.13:00:00 to 2017-01-02.13:00:00 
 *		  (24 hours) and print them to console AND also load them to apache_audit.blocked_hosts with comments on why it's blocked.
 * 
 * @author hans2520
 *
 */
package com.ef;

import java.io.File;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.apache.commons.cli.*;

public class Parser {
	
	private final static Logger logger = LogManager.getLogger();
	
	private final static String ACCESS_LOG_LOAD_DATA_SQL = "LOAD DATA LOCAL INFILE ? INTO TABLE apache_audit.access_log " + 
			"FIELDS TERMINATED BY '|' LINES TERMINATED BY '\\n' (log_date, host_id, request, response, user_agent); ";
 
	private final static String ACCESS_LOG_AUDIT_SQL_START = "SELECT host_id, COUNT(host_id) FROM apache_audit.access_log WHERE " +
			"log_date BETWEEN ? AND DATE_ADD(?, INTERVAL 1 ";
	private final static String ACCESS_LOG_AUDIT_SQL_END = ") GROUP BY host_id HAVING COUNT(host_id) >= ? ";
	
	private final static String HOST_BLACKLIST_INSERT_SQL_START 	= "INSERT INTO apache_audit.host_blacklist " + 
			"(host_id, message, created) VALUES (?, ?, NOW()) ";
	private final static String HOST_BLACKLIST_INSERT_SQL_MIDDLE	=  ",(?, ?, NOW())";
	private final static String HOST_BLACKLIST_INSERT_SQL_END		=  " ON DUPLICATE KEY UPDATE message = ?, updated = NOW();";
	private final static String HOST_BLACKLIST_UPDATE_MESSAGE		=  "Host IP has multiple violations of blacklisted activity.";
	
    public String main(String[] args) throws Exception {

        Options options = new Options();

        Option accesslog = new Option("s", "accesslog", true, "/path/to/file");
        accesslog.setRequired(false);
        options.addOption(accesslog);
        
        Option startDate = new Option("s", "startDate", true, "yyyy-MM-dd.HH:mm:ss format");
        startDate.setRequired(true);
        options.addOption(startDate);

        Option duration = new Option("d", "duration", true, "either \"hourly\" or \"daily\" ");
        duration.setRequired(true);
        options.addOption(duration);
        
        Option threshold = new Option("t", "threshold", true, "an integer");
        threshold.setRequired(true);
        options.addOption(threshold);        

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        String retVal = "";
        try {
            cmd = parser.parse(options, args);
            
            String accesslogValue = cmd.getOptionValue("accesslog");
            String startDateValue = cmd.getOptionValue("startDate");
            String durationValue = cmd.getOptionValue("duration");
            int thresholdValue = Integer.valueOf(cmd.getOptionValue("threshold"));

            System.out.println("accesslog: " + accesslogValue);
            System.out.println("startDate: " + startDateValue);
            System.out.println("duration: " + durationValue);
            System.out.println("threshold: " + thresholdValue);
            System.out.println("SEARCHING . . . ");	
            
            //Convert now to save repeated ops later...
            durationValue = durationValue.equalsIgnoreCase("daily") ? "DAY" : "HOUR";
            
            loadAccessFileIfExistsIntoDB(accesslogValue);
            String[] violationIPs = findIPsExceedingThreshold(startDateValue, durationValue, thresholdValue);
            System.out.println("RESULTS: ");
            if (violationIPs[0].length() > 0) {
            	retVal = printResultsToConsole(violationIPs);
            	addViolatingIPsToBlacklist(violationIPs, durationValue, thresholdValue);
            } else {
            	System.out.println("No IPs found violating threshold of " + duration + " : " + threshold + ".");
            }

        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp(Parser.class.getName(), options);
            formatter.printUsage(new PrintWriter(System.out), 80, Parser.class.getName(), options);
        }
        
        return retVal;

    }
    
    
   /* printResultsToConsole
    * 		@param String[] 2-tuple array of strings, each element is intended to be split into its own array via comma-delimitter 
    * 						This is not checked for saftey!
    * 		@return the entire String it prints out to console (for use with testing).
    */
    String printResultsToConsole(String[] blacklistedIPs) {
    	logger.info("Begin. blacklistedIPs: {}: ", blacklistedIPs);
    	
    	String[] ipArray = blacklistedIPs[0].split(","), countArray = blacklistedIPs[1].split(",");
    	StringBuilder retVal = new StringBuilder(257);
    	retVal.append("-----------------------------------------------------\r\n");
    	retVal.append("      IP Address             Number of hits          \r\n");
    	retVal.append("-----------------------------------------------------\r\n");
    	for (int i = 0; i < ipArray.length; i++) {
    	retVal.append("    " + ipArray[i] + "             "  +  countArray[i] + "      \r\n");
    	}
    	retVal.append("-----------------------------------------------------\r\n");

    	System.out.println(retVal.toString());
    	return retVal.toString();
    }
    
   /* loadAccessFileIfExistsIntoDB
    * 		@param String The full path to the accessLog 
    * 		@return 
    */           
    void loadAccessFileIfExistsIntoDB(String accesslog) {
    	logger.info("Begin. accesslog: {}: ", accesslog);
        if (accesslog != null && !accesslog.isEmpty()) {
        	File logFile = new File(accesslog);
        	if (logFile.exists()) {
        		loadAccessFile(logFile);
        	} else {
        		logger.info("Cannot find input access file {} ", accesslog);
        	}
        }
    };
    

   /* loadAccessFile
    * 		@param File The File object representing the access log
    * 		@return boolean true if LOAD DATA into MySQL succeeded.
    */     
	boolean loadAccessFile(File logFile) {
		logger.info("Begin. logFile: {}: ", logFile);
		boolean retVal = false;
		Connection con = null;
	    PreparedStatement ps = null;
	    ResultSet rs = null;
	    int count = 0;
	    try {
	        String filePath = logFile.getCanonicalPath();
	        logger.info("Canonical Path: {}: ", filePath);
	    	con = DBConnectionManager.getNewConnection();
	        ps = con.prepareStatement(ACCESS_LOG_LOAD_DATA_SQL);
	        ps.setString(1, filePath);
	        logger.trace("Load Data SQL: {} ", ps.toString());
	        if (ps.execute()) {
		        // According to specification for this type of query, we are expecting false to be
		        // returned indicating that an update count is returned. This query would normally be 
		        // executed as executeUpdate, but since we are unioning the column names as a pure select, 
		        // java does not allow this.
	        	logger.warn("ResultSet unexpected for LOAD DATA. Access Log will not be imported.");
		    } else { // the successful case
	        	count = ps.getUpdateCount();
	        	if (count > 0) {
	        		logger.info("{} successfully imported with {} logs inserted.", filePath, count);
	        		retVal = true;
	        	} else {
	        		logger.warn("No data imported. Either {} contains no data, is improperly formatted, or " + 
	        					"contains only duplicate log statements.", filePath);
	        	}
	        }
	    } catch (SQLException e) {
	         logger.error("Database connection problem!", e);
	    } catch (Throwable t) {
	         logger.error("Unknown Exception!", t);
	    } finally {
	        try {
	        	if (rs != null)
	        		rs.close();
	        	if (ps != null)
	        		ps.close();
	        	if (con != null)
	        		con.close();
	        } catch (SQLException e) {
	        	logger.error("Exception closing connections!", e);
	        }
		}
	    logger.info("End.");
	    return retVal;
	}


   /* findIPsExceedingThreshold
    * 		@param String The datetime that mysql can recognize (no saftey checks!)
    * 		@param String Either "HOUR" or "DAY"
    * 		@param int an integer 
    * 		@return String[] 2-tuple array of strings, each element is itself a comma-delimmited string 
    * 				of the blacklisted IPs and the offending counts, respectively.
    */ 	
	String[] findIPsExceedingThreshold(String startDate, String duration, int threshold) {
		logger.info("Begin. startDate: {}, duration {}, threshold {}", startDate, duration, threshold);
		String[] retVal = {"", ""};
		Connection con = null;
	    PreparedStatement ps = null;
	    ResultSet rs = null;
	    StringBuilder violationIPs = new StringBuilder(), violationCounts = new StringBuilder();
	    try {
	    	con = DBConnectionManager.getNewConnection();
	        ps = con.prepareStatement(ACCESS_LOG_AUDIT_SQL_START + duration + ACCESS_LOG_AUDIT_SQL_END);
	        ps.setString(1, startDate);
	        ps.setString(2, startDate);
	        ps.setInt(3, threshold);
	        logger.trace("Audit SQL: {} ", ps.toString());
	        rs = ps.executeQuery();
	        if (rs != null && rs.isBeforeFirst()) {
				while (rs.next()) {
		        	violationIPs.append(rs.getString(1)).append(",");
		        	violationCounts.append(rs.getString(2)).append(",");
				}
				
	        } 
	        
	        if (violationIPs.length() > 0) {
	        	retVal[0] = violationIPs.toString();
	        	retVal[1] = violationCounts.toString();
	        } else {
	        	logger.info("No IPs found violating threshold of {} : {}", duration, threshold);
	        }
	    } catch (SQLException e) {
	         logger.error("Database connection problem!", e);
	    } catch (Throwable t) {
	         logger.error("Unknown Exception!", t);
	    } finally {
	        try {
	        	if (rs != null)
	        		rs.close();
	        	if (ps != null)
	        		ps.close();
	        	if (con != null)
	        		con.close();
	        } catch (SQLException e) {
	        	logger.error("Exception closing connections!", e);
	        }
		}
	    logger.info("End.");
	    return retVal;
	}
	

   /* findIPsExceedingThreshold
    * 		@param String[] 2-tuple array of strings, each element is intended to be split into its own array via comma-delimitter 
    * 						This is not checked for saftey!
    * 		@param String Either "HOUR" or "DAY"
    * 		@param int an integer 
    * 		@return 
    */ 
	void addViolatingIPsToBlacklist(String[] blacklistedIPs, String duration, int threshold) {
		logger.info("Begin. blacklistedIPs: {}", blacklistedIPs);
		Connection con = null;
	    PreparedStatement ps = null;
	    ResultSet rs = null;

	    try {	    	
	    	String[] ipArray = blacklistedIPs[0].split(","), countArray = blacklistedIPs[1].split(",");
	    	String blacklistSql = HOST_BLACKLIST_INSERT_SQL_START;
	        for (int i = 1; i < ipArray.length; i++) {
	        	blacklistSql += HOST_BLACKLIST_INSERT_SQL_MIDDLE;
	        }
	        blacklistSql += HOST_BLACKLIST_INSERT_SQL_END;
	        
	    	con = DBConnectionManager.getNewConnection();
	        ps = con.prepareStatement(blacklistSql);
	        int j = 1;
	        for (int i = 0; i < ipArray.length; i++) { 
		        ps.setString(j++, ipArray[i]);
		        String message = "Host IP generated traffic of " + countArray[i] + " hits in one " + duration +
		        			     ", exceeding input threshold of " + threshold + ".";
		        ps.setString(j++, message);
	        }
	        ps.setString(j++, HOST_BLACKLIST_UPDATE_MESSAGE);
	        logger.trace("Blacklist IP SQL: {} ", ps.toString());
	        
	        int rowsUpdated = ps.executeUpdate();
	        if (rowsUpdated > 0) {
	        	logger.info("Successfully uploaded {} entries into blacklist.", rowsUpdated);
	        } else {
	        	logger.error("FAILED to update blacklist.");
	        }
	    }  catch (SQLException e) {
	         logger.error("Database connection problem!", e);
	    } catch (Throwable t) {
	         logger.error("Unknown Exception!", t);
	    } finally {
	        try {
	        	if (rs != null)
	        		rs.close();
	        	if (ps != null)
	        		ps.close();
	        	if (con != null)
	        		con.close();
	        } catch (SQLException e) {
	        	logger.error("Exception closing connections!", e);
	        }
		}
	    logger.info("End.");
	}

}