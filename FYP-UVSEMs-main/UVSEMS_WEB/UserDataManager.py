import base64
import bcrypt
from flask import request, session
from mysql.connector import Error
from Audit import Audit
from EncryptionHandler import decrypt_data, hash_salt_pw,generate_keynonce,encrypt_data
from SecurityManager import SecurityManager


class UserDataManager:
    def __init__(self, dbConnection):
            self.dbConnection = dbConnection
            self.auditer = Audit(dbConnection)
            self.securityManager = SecurityManager(dbConnection)
            
            
            
    def validate_login(self, username, inputPassword):
        """
        v.08
        This is used when a user attempts to login to the system. It connects to the UVASEM database and then does a check 
        that looks to see if the username + password combination is found in the database. 
        On a successful login attempt the database will be updated with the log in time for audit purposes.
        Implemented Security Lock-out features from the SecurityManager class.

        Args:
            username (str): This is the username of the user attempting to log in.
            inputPassword (str): This is the password provided by the user for login.

        Returns:
            dict: Result of the login attempt with success status and a message.
        """        
        if self.securityManager.is_locked_out(username):
                return {'success': False, 'message': 'Account is locked due to too many failed login attempts'}
        
        
        connection = self.dbConnection.createConnection()
        if connection is None or not connection.is_connected():
            print("Failed to connect to the database at function")
            return {'success': False, 'message': 'Database connection failed'}

        cursor = connection.cursor(prepared=True)

        try:
            query = "SELECT password, UserID, AccessLevel, Role FROM Users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()

            if result:
                storedHash, user_id, access_level, role = result
                if bcrypt.checkpw(inputPassword.encode(), storedHash.encode()):
                    updateQuery = "UPDATE Users SET LastLogInTime = NOW() WHERE username = %s"
                    cursor.execute(updateQuery, (username,))
                    connection.commit()
                    return {'success': True, 'user_id': user_id, 'access_level': access_level, 'role':role}
                else:
                    self.securityManager.record_failed_login(username, request.remote_addr, request.headers.get('User-Agent'))
                    return {'success': False, 'message': '⚠️ Invalid credentials provided'}
            else:
                self.securityManager.record_failed_login(username, request.remote_addr, request.headers.get('User-Agent'))
                return {'success': False, 'message': '⚠️ Invalid credentials provided'}

        except Error as e:
            print(f"Error: {e}")
            return {'success': False, 'message': str(e)}

        finally:
            cursor.close()
            connection.close()


    def get_next_userId(self):
            """
                v.02
                Grabs the next available UserID from the Database, so if the last user was 3 then this will pull a result of 4.
                This is used to display the next user id on the new user form.

                Returns:
                    int: The next available user ID (or 1 if no users are found or in case of an error).
                """        
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            try:
                query = "SELECT MAX(UserID) FROM Users"
                cursor.execute(query,)
                maxId = cursor.fetchone()[0]
                return maxId + 1 if maxId else 1 
            except Error as e:
                print(f"Error: {e}")
                return 1 
            finally:
                cursor.close()
                connection.close()

    def save_new_user(self, userData):
        """
        v.08
        This function handles saving a new user in the database, calls encryption methods and hashing+salting for passwords.

        Args:
            userData (dict): A dictionary which contains all the user data. 

        Returns:
            bool: True if the user is successfully added to the database otherwise would be False.
        """
        loggedin_user = session.get("username") 
        userId = self.get_next_userId()  
        hashed_pw = hash_salt_pw(userData["password"])  
        
        if self.username_duplicate_check(userData["username"]):
            return {'success': False, 'message': '❗ This Username already exists'}
    
        key, nonce = generate_keynonce()
        
        encryptedFirstName = encrypt_data(userData["firstName"], key, nonce)
        encryptedLastName = encrypt_data(userData["lastName"], key, nonce)
        #encryptedRole = encryptData(userData["role"], key, nonce)
        role = int(userData["role"])
        encryptedEmail = encrypt_data(userData["email"], key, nonce)
        encryptedPhone = encrypt_data(userData["phone"], key, nonce)
        access_level = int(userData.get("accessLevel", 2))

        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the main database")
            return False

        cursor = connection.cursor(prepared=True)
        try:
            insertUserQuery = "INSERT INTO Users (Username, Fname, Lname, Password, Role, Email, Phone, Author,CreatedTime, AccessLevel) VALUES (%s, %s, %s, %s, %s, %s, %s, %s,NOW(),%s)"
            cursor.execute(
                insertUserQuery,
                (
                    userData["username"],
                    encryptedFirstName,
                    encryptedLastName,
                    hashed_pw,
                    role,
                    encryptedEmail,
                    encryptedPhone,
                    loggedin_user,
                    access_level
                ),
            )
            connection.commit()
            userId = cursor.lastrowid

            # convert to Base64 otherwise SQL gets mad
            key64 = base64.b64encode(key).decode('utf-8')
            nonce64 = base64.b64encode(nonce).decode('utf-8')
            
            if not self.save_encryption_key(userId, key64, nonce64): 
                raise Exception("Failed to save encryption key and/or the nonce!")

            return True
        except Error as e:
            print(f"Error in saveNewUser: {e}")
            return False
        finally:
            cursor.close()
            connection.close()

    

                
    def count_every_users(self):
        
        """
        v.01
        Real simple SQL query - grabs all the users in the user table
        
        Returns:
            int: The total number of users from the Users table.
        """
        connection = self.dbConnection.createConnection()
        cursor = connection.cursor(prepared=True)
        try:
            query = "SELECT COUNT(*) FROM Users"
            cursor.execute(query)
            result = cursor.fetchone()
            return result[0] if result else 0
        except Error as e:
            print(f"Error: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()
            
    def count_redundant_users(self):
        """
            v.01
            THis counts the number of users who are considered redundant/inactive based on their last login time.
            A user would be considered inactive if they have either never logged in (LastLoginTime is NULL)
            or if their last login was a 1 year+ ago. 

            Returns:
                int: The count of redundant/inactive users.
        """
        
        connection = self.dbConnection.createConnection()
        cursor = connection.cursor(prepared=True)
        try:
            # one_year_ago = datetime.now() - timedelta(days=365)
           # one_year_ago_formatted = one_year_ago.strftime('%Y-%m-%d')
           
           
            query = "SELECT COUNT(*) FROM Users WHERE LastLoginTime IS NULL OR LastLoginTime <= (NOW() - INTERVAL 1 YEAR)"
            cursor.execute(query)
            result = cursor.fetchone()
            return result[0] if result else 0
        except Error as e:
            print(f"Error: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()                   
                
    def get_role_counts(self):
        connection = self.dbConnection.createConnection()
        cursor = connection.cursor(prepared=True)
        try:
            query = "SELECT Role, COUNT(*) FROM Users GROUP BY Role"
            cursor.execute(query)
            result = cursor.fetchall()
            return dict(result)  
        except Error as e:
            print(f"Error: {e}")
            return {}
        finally:
            cursor.close()
            connection.close()
    
                
    def get_current_logged_in_users(self):
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            try:
                # Let's assume an active user is one who has logged in less than 30 minutes ago? 
                # Problem for later is if "User" is still logged in an hour later he will no longer be counted.
                query = """
                SELECT COUNT(*)FROM Users WHERE LastLoginTime > (NOW() - INTERVAL 30 MINUTE) 
                """
                cursor.execute(query)
                result = cursor.fetchone()
                return result[0] if result else 0
            except Error as e:
                print(f"Error: {e}")
                return 0
            finally:
                cursor.close()
                connection.close()
                
    def save_encryption_key(self, userId, key, nonce):
        """
        v.06
        Saves an encryption key and also the nonce in the KeyBank database associated with a specific given user ID.

        This method connects to the KeyBank db and inserts the provided encryption key+nonce into the UserBank table and the key and nonce are 
        associated with the provided user ID.

        Args:
            userId (int): The user ID that is associated with the encryption key.
            key (str): The encryption key to be saved.
            nonce (str): The nonce to be saved.

        Returns:
            bool: True if the key and nonce are successfully saved, otherwise False.
        """

        
        keybank_connection = self.dbConnection.createKeyBankConnection()
        if keybank_connection is None:
            print("Failed to connect to the KeyBank database")
            return False
        cursor = keybank_connection.cursor(prepared=True)
        try:
            insertKeyAndNonceQuery = "INSERT INTO UserBank (UserID, `Key`, Nonce) VALUES (%s, %s, %s)"
            cursor.execute(insertKeyAndNonceQuery, (userId, key, nonce))
            keybank_connection.commit()
        except Error as e:
            print(f"Error saving encryption key and nonce: {e}")
            keybank_connection.rollback()
            return False
        finally:
            cursor.close()
            keybank_connection.close()
        return True

        
    def pull_encryption_key_non(self, userId):
        """
        v.02
        Pulls the encryption key and nonce out of the KeyBank database.

        Args:
            userId (int): The user ID for which to retrieve the encryption key and nonce.

        Returns:
            tuple: A tuple containing the base64-encoded encryption key and nonce, 
                or (None, None) if an error occurs or if the user is not found.
        """
        connection = self.dbConnection.createKeyBankConnection()
        if connection is None:
            print("Failed to connect to the KeyBank database :( )")
            return None, None

        cursor = connection.cursor(prepared=True)
        
        try:
            selectKeyAndNonceQuery = "SELECT `Key`, `Nonce` FROM UserBank WHERE UserID = %s"
            cursor.execute(selectKeyAndNonceQuery, (userId,))   
            result = cursor.fetchone()   
            
            # IMPORTANT: Decode the nonce and key, otherwise you will get B64 Trash.
            if result is not None:
                key, nonce = result
                key = base64.b64decode(key)
                nonce = base64.b64decode(nonce)
                return key, nonce
            else:
                print(f"User ID {userId} not found in the database.")
                return None, None
        except Exception as e:
            print(f"Error retrieving encryption key and nonce: {str(e)}")
            return None, None
        finally:
            cursor.close()
            connection.close()

    def username_duplicate_check(self, username):
        """
        v.01
        Checks if a username already exists in the database, because if it does indeed have a duplicate
        without this check you will have a bad time...

        Args:
            username (str): Username to check.

        Returns:
            bool: True if username exists, False otherwise.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            return False

        cursor = connection.cursor(prepared=True)
        try:
            query = "SELECT COUNT(*) FROM Users WHERE Username = %s"
            cursor.execute(query, (username,))
            (count,) = cursor.fetchone()
            return count > 0
        except Error as e:
            print(f"Error: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
            
    def get_user_data(self):
            """
            v.01
        Fetches all users from the database and decrypts their information.

        Returns:
            list: A list of dictionaries containing decrypted user data.
        """
            connection = self.dbConnection.createConnection()
            if connection is None:
                print("Failed to connect to the main database")
                return []

            cursor = connection.cursor(prepared=True)
            try:
                query = "SELECT UserID, Username, Fname, Lname, Role, Email, Phone, AccessLevel FROM Users"
                cursor.execute(query)
                users = cursor.fetchall()

                decrypted_users = []
                for user in users:
                    user_id, username, encrypted_fname, encrypted_lname, role, encrypted_email, encrypted_phone, access_level = user
                    
                    key, nonce = self.pull_encryption_key_non(user_id)
                    if key is None or nonce is None:
                        print(f"Cannot get the key or nonce for specified user ID {user_id}")
                        continue  

                    fname = decrypt_data(encrypted_fname, key, nonce)
                    lname = decrypt_data(encrypted_lname, key, nonce)
                    email = decrypt_data(encrypted_email, key, nonce)
                    phone = decrypt_data(encrypted_phone, key, nonce)

                    decrypted_users.append({
                        'UserID': user_id,
                        'Username': username,
                        'Fname': fname,
                        'Lname': lname,
                        'Role': role,  
                        'Email': email,
                        'Phone': phone,
                        'AccessLevel': access_level
                    })

                return decrypted_users
            except Exception as e:
                print(f"Error fetching and decrypting user data: {str(e)}")
                return []
            finally:
                cursor.close()
                connection.close()
                
    def update_user_data(self, userId, updatedData):
        """
        v.01
        Used to update a users details and send the required data to the database.
        A new nonce and key are not required and the previous one will be used for
        encryption.

        Args:
            userId (int): The ID of the user to update.
            updatedData (dict): A dictionary containing the updated user data.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the main database")
            return False

        try:
            key, nonce = self.pull_encryption_key_non(userId)
            if key is None or nonce is None:
                print(f"Cannot get the key or nonce for specified user ID {userId}")
                return False

            encryptedFirstName = encrypt_data(updatedData["fname"], key, nonce)
            encryptedLastName = encrypt_data(updatedData["lname"], key, nonce)
            encryptedEmail = encrypt_data(updatedData["email"], key, nonce)
            encryptedPhone = encrypt_data(updatedData["phone"], key, nonce)

            updateQuery = """
                UPDATE Users
                SET Username = %s, Fname = %s, Lname = %s, Role = %s, Email = %s, Phone = %s, AccessLevel = %s
                WHERE UserID = %s
            """
            cursor = connection.cursor(prepared=True)
            cursor.execute(
                updateQuery,
                (
                    updatedData["username"],
                    encryptedFirstName,
                    encryptedLastName,
                    updatedData["role"],
                    encryptedEmail,
                    encryptedPhone,
                    updatedData["accessLevel"],
                    userId
                ),
            )
            connection.commit()

            return True
        except Error as e:
            print(f"Error in updateUser: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
            
            
    def get_analysts(self):
        """
        v.2
        gets all users with Role = 3 (Analysts) from the Users table.
        
        Returns:
            list of dict: A list of dictionaries, each representing an analyst with their details.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database. boo.")
            return []

        analysts = []
        try:
            cursor = connection.cursor(dictionary=True)  
            query = "SELECT UserID, Username FROM Users WHERE Role = 3"
            cursor.execute(query)
            for row in cursor:
                analysts.append(row)  
        except Error as e:
            print(f"Error fetching analysts: {e}")
        finally:
            cursor.close()
            connection.close()

        return analysts
    
    def get_engineers(self):
        """
        v1
        pulls all the users with Role = 4 (Engineer) from the Users table.
        
        Returns:
            list of dict: A list of dictionaries, each representing an analyst with their details.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        engineers = []
        try:
            cursor = connection.cursor(dictionary=True)  
            query = "SELECT UserID, Username FROM Users WHERE Role = 4"
            cursor.execute(query)
            for row in cursor:
                engineers.append(row)  # Each row is a dict now due to cursor(dictionary=True) which is a thing apparantley - USE FROM NOW
        except Error as e:
            print(f"Error fetching analysts: {e}")
        finally:
            cursor.close()
            connection.close()

        return engineers
    
    def get_assigned_analyst(self, scan_id):    
        """
        v.2
        Gets the assigned analyst for x scan. 
        
        Returns:
            list of dict: A list of dictionaries, each representing an analyst with their details.
        """
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return None

        try:
            cursor = connection.cursor()
            query = "SELECT AssignedAnalyst FROM Scans WHERE ScanID = %s;"
            cursor.execute(query, (scan_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Error fetching assigned analyst: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
            
    def get_assigned_engineer(self, scan_id):    
        """
        v.1
        Gets the assigned engineer for x scan. 
        
        Returns:
            list of dict: A list of dictionaries, each representing an engineeer with their details.
        """
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return None

        try:
            cursor = connection.cursor()
            query = "SELECT AssignedEngineer FROM Scans WHERE ScanID = %s;"
            cursor.execute(query, (scan_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Error fetching enginner analyst: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
            
    def get_username(self, user_id):    
        """
        v.1
        Gets the username for a given enginner
        
        Returns:
            list of dict: A list of dictionaries, each representing an engineeer with their details.
        """
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return None

        try:
            cursor = connection.cursor()
            query = "SELECT Username FROM Users WHERE UserID = %s;"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Error fetching enginner analyst: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
            

            
    def update_assigned_analyst(self,scan_id, new_assigned_analyst_id):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            
            # THe creation of notes could be created at the creation of the scan
            # But I decided to add it to this level instead as it is directly associated with
            # an analyst or enginner. In the "GRAND scheme" of things it makes little difference
            # but this code needs to be placed somewherefor the notes to work for the other roles.
            # First runs a query based on scan_id to see if notes exisit for a specific scan
            cursor.execute("SELECT AnaNotes FROM ScanNotes WHERE ScanID = %s", (scan_id,))
            notes_exist = cursor.fetchone()

            # If there is no ScanNotes entry for a specific scan then one is created here.
            if not notes_exist:
                cursor.execute("INSERT INTO ScanNotes (ScanID) VALUES (%s)", (scan_id,))
                
            status = "Awaiting Review"
            update_query = """
                UPDATE Scans
                SET AssignedAnalyst = %s
                WHERE ScanID = %s
            """
            cursor.execute(update_query, (new_assigned_analyst_id,scan_id))
            connection.commit()
            print("Assigned analyst updated successfully.")
            success = True
        except Exception as e:
            print(f"Error updating assigned analyst: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        return success
    
    def update_assigned_engineer(self, scan_id, new_assigned_engineer_id):
        connection = None
        cursor = None
        success = False  
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            status = "Remediation Pending"
            update_query = """
                UPDATE Scans
                SET AssignedEngineer = %s, Status = %s
                WHERE ScanID = %s
            """
            cursor.execute(update_query, (new_assigned_engineer_id, status, scan_id))
            connection.commit()
            print("Assigned engineer updated successfully.")
            success = True
        except Exception as e:
            print(f"Error updating assigned engineer: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        return success