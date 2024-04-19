import mysql.connector
from mysql.connector import Error


class DBConnectionHandler:
    def __init__(self, configs):
        
        self.configs = configs
        # Standard DB
        self.host = configs.host
        self.port = configs.port
        self.user = configs.user
        self.password = configs.password
        self.database = configs.database
        # The "Other"  DB
        self.keyBankHost = configs.keyBankHost
        self.keyBankPort = configs.keyBankPort
        self.keyBankUser = configs.keyBankUser
        self.keyBankPassword = configs.keyBankPassword
        self.keyBankDatabase = configs.keyBankDatabase


#### Use (prepared=True) for Prepared statements
#### Init cursor, set query var, execute, pull result from cursor / fetcone() or fetchall() 
#### finally block close cursor, close connection

    def getSecretKey(self):
        connection = self.createKeyBankConnection()  
        if connection is None or not connection.is_connected():
            print("Failed to connect to the Key Manager database")
            return None

        cursor = connection.cursor()
        try:
            cursor.execute("SELECT SecretKey FROM FlaskKey WHERE KeyID = 1")
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Error fetching secret key: {e}")
            return None
        finally:
            cursor.close()
            connection.close()



    def fetchEncryptionKey(self, userId):
        """
            Picks out the specific users key which is associated with their user ID.
            
            Links up to the KeyBank database and executes a query to grab the encryption key for a speicfic user.
            Calls the connection method to create a connection to the db, executes the query and then picks up the key.

            Args:
                userId (int): The user ID for their specific encryption key.

            Returns:
                str: The encryption key (as a string) if its there and found, or None if no key is found (or on error).
        """
        connection = self.createKeyBankConnection()
        if connection is None or not connection.is_connected():
            print("Failed to connect to the Key Manager database")
            return None

        # Initialise the cursor the first
        cursor = connection.cursor()

        try:
            # Execute the query here and fetchone record which is the key
            cursor.execute("SELECT Key FROM UserBank WHERE UserID = %s", (userId,))
            keyRecord = cursor.fetchone()

            # Check if a record is found and return the encryption key.
            # If no record is found (keyRecord is None) then gotta return None to indicate that no key was found.
            return keyRecord[0] if keyRecord else None

        except Error as e:
            print(f"Error fetching encryption key: {e}")
            return None
        finally:
            # Close the cursor and the database connection in the 'finally' block - keep it all clean
            if cursor:
                cursor.close()
            if connection:
                connection.close()

  
    def createConnection(self):
        """
            Creates and then returns a connection to the Database.
            
            This method uses the set config settings for the central (UVASEMS) database which includes the host, port, user, password, and 
            database name in order to create a database connection.

            Returns:
                MySQLConnection: A MySQL connection object if the connection is successful or nothing if the connection error.
        """
        
        try:
            connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
            )
            return connection
        except Error as e:
            print(f"Error connecting to MySQL Database: {e}")
            return None


    def createKeyBankConnection(self):
        
        """
        Creates a connection to the KeyBank Database, this had to be created as the same code was being used repeatly too often and
        therefore it makes far more sense to have a dedidcated function for the connection.
        Works in the same manner as the CreateConnection function just uses the alternate configuration settings specifically for the KeyBank database, 
        including the host, port, user, password, and database name, to create a database connection.

        Returns:
            MySQLConnection: A MySQL connection object if the connection is successful or nothing if the connection fails to connect.
        """
        try:
            keyBankConnection = mysql.connector.connect(
                host=self.keyBankHost,
                port=self.keyBankPort,
                user=self.keyBankUser,
                password=self.keyBankPassword,
                database=self.keyBankDatabase,
            )
            return keyBankConnection
        except Error as e:
            print(f"Error connecting to KeyBank Database: {e}")
            return None

            
    def executeQuery(self, query, params=None):
        
        """
    Executes an SQL query with set parameters.

    Typically would be used to execute any given SQL query, which can be any valid SQL statement 
    including SELECT, INSERT, UPDATE, DELETE, etc and It commits the changes after executing the query.

    Args:
        query (str): The SQL query set to be executed.
        params (tuple, optional): Optional parameters to be used in the query. Default = None.

    Returns:
        None: No Return value but a success message/error message based on xecution.
    """
        connection = self.createConnection()
        cursor = connection.cursor()
        try:
            cursor.execute(query, params)
            connection.commit()
            print("Query successful")
        except Error as e:
            print(f"Error: {e}")
        finally:
            cursor.close()
            connection.close()
            
