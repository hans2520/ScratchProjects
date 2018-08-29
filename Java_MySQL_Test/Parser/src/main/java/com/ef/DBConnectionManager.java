package com.ef;
 
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import javax.sql.DataSource;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class DBConnectionManager {
 
	private final static Logger logger = LogManager.getLogger();
    private final static Context envContext = getInitialContext();
    private final static String MYSQL_DRIVER_NAME = "com.mysql.jdbc.Driver";
 	private final static String DEFAULT_DATABASE = "apache_audit";
	private final static String MYSQL_DEFAULT_URL = "jdbc:mysql://localhost/apache_audit?useUnicode=true&amp;characterEncoding=UTF-8&amp;relaxAutoCommit=true&amp;useSSL=false";
	private final static String MYSQL_DEFAULT_USER = "root";
	private final static String MYSQL_DEFAULT_PASSWORD = "P@ssw0rd";

    private final static Context getInitialContext() {
    	try {
    		return new InitialContext();
    	} catch (NamingException e) {
    		logger.fatal("Could not get initial context!", e);
    	}
    	return null;
    }
   
    /* 
     * Single-connection model -- to be opened on application startup and closed only on application shutdown.
     */
    private Connection connection = null;
    
    public DBConnectionManager() throws SQLException, InstantiationException, IllegalAccessException, ClassNotFoundException {
    	this(DEFAULT_DATABASE);
    }
     
    public DBConnectionManager(String databaseName) throws SQLException, InstantiationException, IllegalAccessException, ClassNotFoundException {
        this.connection = getNewConnection(databaseName);
    }
    
	// Always returns the same connection, never get a new one. 
    public Connection getStaticConnection() {
        return this.connection;
    }
    
    /* 
     * Connection Pool model -- connections should be opened and closed for each operation.
     */
    public static Connection getNewConnection() throws SQLException, InstantiationException, IllegalAccessException, ClassNotFoundException {
    	return getNewConnection(DEFAULT_DATABASE);
    }
    
    public static Connection getNewConnection(String databaseName) throws SQLException, 
    																	  InstantiationException, 
    																	  IllegalAccessException, 
    																	  ClassNotFoundException {
    	Connection con = null;
        try {
            if (databaseName == null || databaseName.isEmpty()) {
            	databaseName = DEFAULT_DATABASE;
            }
        	DataSource ds = (DataSource)envContext.lookup("java:/comp/env/jdbc/" + databaseName);
            if (ds != null) {
            	con = ds.getConnection();
            }
            if (con == null) {
            	throw new SQLException("Unable to get database connection from JNI.");
            }
            
        } catch (NamingException e) {
        	//logger.error("Datasource 'java:/comp/env/jdbc/" + databaseName + "' does not exist.",  e);
        } catch (SQLException e) {
        	logger.error(e.getMessage(),  e);
        } finally {
        	if (con == null) {
        		Class.forName(MYSQL_DRIVER_NAME).newInstance();
	            con = DriverManager.getConnection(MYSQL_DEFAULT_URL, MYSQL_DEFAULT_USER, MYSQL_DEFAULT_PASSWORD);
        	}
        }
        
        return con;
    }
    
}