import base64
from flask import request
from mysql.connector import Error
from EncryptionHandler import decrypt_data, encrypt_data, generate_keynonce

class Audit:
    def __init__(self, dbConnection):
        self.dbConnection = dbConnection

    def log_audit_entry(self, user_id, action, description, ip_address, browser_info, severity_level, category, details):
        """
        The master function to log - Takes every parameter which can be customised based on action.
        The data is encrypted when it is passed into the db
        v.01

        Args:
        - user_id (str): The ID of the user associated with the audit log.
        - action (str): The action performed by the user.
        - description (str): A description of the action.
        - ip_address (str): The IP address from which the action was performed.
        - browser_info (str): Information about the browser used for the action.
        - severity_level (str): The severity level of the action.
        - category (str): The category of the action.
        - details (str): Detailed information about the action.

        """

        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Connection tu database failed")
            return

        cursor = connection.cursor(prepared=True)
        try:
            # Generate key and nonce for encryption
            key, nonce = generate_keynonce()

            # Encrypt the fields that require encryption
            encryptedAction = encrypt_data(action, key, nonce)
            encryptedDescription = encrypt_data(description, key, nonce)
            encryptedIPAddress = encrypt_data(ip_address, key, nonce)
            encryptedBrowserInfo = encrypt_data(browser_info, key, nonce)
            encryptedDetails = encrypt_data(details, key, nonce)
            encryptedCategory = encrypt_data(category, key, nonce)

            # Start transaction
            connection.start_transaction()

            # Insert the audit log entry with encrypted details
            query = """
            INSERT INTO AuditLog (UserID, Action, Description, Timestamp, IPAddress, BrowserInfo, SeverityLevel, Category, Details)
            VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (user_id, encryptedAction, encryptedDescription, encryptedIPAddress, encryptedBrowserInfo, severity_level, encryptedCategory, encryptedDetails))
            log_id = cursor.lastrowid  # Get the auto-incremented LogID

            # Convert key and nonce to Base64 for storage
            key64 = base64.b64encode(key).decode('utf-8')
            nonce64 = base64.b64encode(nonce).decode('utf-8')

            # Save key and nonce in KeyLog table for later decryption
            self.save_encryption_logKey(log_id, key64, nonce64)

            # Commit transaction
            connection.commit()

        except Error as e:
            # Rollback in case of error
            connection.rollback()
            print(f"An error has occurred in the logging system, transaction rolled back: {e}")

        finally:
            cursor.close()
            connection.close()
        

    
    def logInvalidLoginAttempt(self, username, ipAddress, category="Authentication"):
        details = f"Attempted Username: {username}"
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Connection to database failed")
            return

        cursor = connection.cursor()
        try:
            key, nonce = generate_keynonce()

            encryptedAction = encrypt_data('Invalid Login Attempt', key, nonce)
            encryptedDescription = encrypt_data('Attempt to log in with invalid credentials', key, nonce)
            encryptedIPAddress = encrypt_data(ipAddress, key, nonce)
            encryptedDetails = encrypt_data(details, key, nonce)
            encryptedCategory = encrypt_data(category, key, nonce)

            query = """
            INSERT INTO AuditLog (Action, Description, IPAddress, Details, Category)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (encryptedAction, encryptedDescription, encryptedIPAddress, encryptedDetails, encryptedCategory))
            log_id = cursor.lastrowid  
            connection.commit()

            # Convert the key and nonce to Base64 for storage otherwise bad times
            key64 = base64.b64encode(key).decode('utf-8')
            nonce64 = base64.b64encode(nonce).decode('utf-8')


            self.save_encryption_logKey(log_id, key64, nonce64)
            
        except Error as e:
            print(f"An error has occurred in the logging system: {e}")
            
        finally:
            cursor.close()
            connection.close()
            
    def save_encryption_logKey(self, log_id, key, nonce):
            connection = self.dbConnection.createKeyBankConnection()
            if connection is None:
                print("Failed to connect to the KeyBank database")
                return False
            cursor = connection.cursor()
            try:
                insertKeyAndNonceQuery = "INSERT INTO LogKey (LogID, `Key`, Nonce) VALUES (%s, %s, %s)"
                cursor.execute(insertKeyAndNonceQuery, (log_id, key, nonce))
                connection.commit()
            except Error as e:
                print(f"Error saving encryption key and nonce: {e}")
                return False
            finally:
                cursor.close()
                connection.close()
            return True

    def get_latest_auditlog(self):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {'action': 'Error connecting to database', 'timestamp': 'N/A'}

        cursor = connection.cursor()
        try:
            query = "SELECT Action, Timestamp, LogID FROM AuditLog ORDER BY Timestamp DESC LIMIT 1"
            cursor.execute(query)
            result = cursor.fetchone()

            if not result:
                return {'action': 'No Data', 'timestamp': 'N/A'}

            encrypted_data, timestamp, log_id = result
            key, nonce = self.pull_encryption_key(log_id)
            
            if not key or not nonce:
                return {'action': 'Error fetching key/nonce', 'timestamp': timestamp}

            try:
                decrypted_data = decrypt_data(encrypted_data, key, nonce)
            except Exception as e:
                print(f"Decryption error for log ID: {log_id}: {e}")
                return {'action': 'DECRYPT FAIL', 'timestamp': timestamp}
            return {'action': decrypted_data, 'timestamp': timestamp}
        except Error as e:
            print(f"SQL ERror: {e}")
            return {'action': 'SQL Error', 'timestamp': 'N/A'}
        finally:
            cursor.close()
            connection.close()
            
    def pull_encryption_key(self, log_id):
        connection = self.dbConnection.createKeyBankConnection()
        if connection is None:
            print("Failed to connect to the KeyBank database")
            return None, None

        cursor = connection.cursor()
        try:
            query = "SELECT `Key`, `Nonce` FROM LogKey WHERE LogID = %s" # DON'T FORGET THE ` FOR KEYWORDS 
            cursor.execute(query, (log_id,))
            result = cursor.fetchone()

            if result:
                key, nonce = result
                key = base64.b64decode(key)
                nonce = base64.b64decode(nonce)
               # print(f"DLog ID: {log_id}, DKey: {key}, DNonce: {nonce}")  # Debugging 
                return key, nonce
            else:
                print(f"Log ID {log_id} not found in the LogKey database.")
                return None, None
        except Exception as e:
            print(f"Error retrieving encryption key and nonce: {str(e)}")
            return None, None
        finally:
            cursor.close()
            connection.close()
    

    def get_all_action_count(self):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}

        try:
            cursor = connection.cursor()
            query = "SELECT LogID, Action FROM AuditLog"
            cursor.execute(query)
            logs = cursor.fetchall()

            action_counts = {}
            for log in logs:
                log_id, encrypted_action = log

                key, nonce = self.pull_encryption_key(log_id)
                if key is None or nonce is None:
                    print(f"Cannot get the key or nonce for specified log ID {log_id}")
                    continue  

                decrypted_action = decrypt_data(encrypted_action, key, nonce)
                #
                if decrypted_action in action_counts:
                    action_counts[decrypted_action] += 1
                else:
                    action_counts[decrypted_action] = 1

            return action_counts

        except Exception as e:
            print(f"Error fetching and decrypting actions: {str(e)}")
            return {}

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
           

    def logUserDataChange(self, changer_user_id, changed_user_id, changed_username):
        """
        When a user makes a change using the manage user page, this action is logged.
        This function is responsbile for creating that log.

        Args:
            changer_user_id (int): UserID of the user who made the changes.
            changed_user_id (int): UserID of the user whose data was changed.
            changed_username (str): Username of the user whose data was changed.
        """
        description = f"{changer_user_id} changed the data of {changed_user_id}:{changed_username}"
        category = "User Data Change"
        details = f"{changer_user_id} changed the data of {changed_user_id}:{changed_username}"
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Connection to database failed")
            return

        cursor = connection.cursor()
        try:
            key, nonce = generate_keynonce()

            encryptedAction = encrypt_data('User Data Change', key, nonce)
            encryptedDescription = encrypt_data(description, key, nonce)
            encryptedCategory = encrypt_data(category, key, nonce)
            encryptedDetails = encrypt_data(details, key, nonce)

            query = """
            INSERT INTO AuditLog (UserID, Action, Description, Category, Details)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (changer_user_id, encryptedAction, encryptedDescription, encryptedCategory, encryptedDetails))
            log_id = cursor.lastrowid  
            connection.commit()
            key64 = base64.b64encode(key).decode('utf-8')
            nonce64 = base64.b64encode(nonce).decode('utf-8')

            self.save_encryption_logKey(log_id, key64, nonce64)
            
        except Error as e:
            print(f"An error has occurred in the logging system: {e}")
            
        finally:
            cursor.close()
            connection.close()

    def get_audit_log_data(self):
        """
        v.03 - Decode block added straight into function
        Gets the audit log db entries

        Returns:
            list: A list of dictionaries containing decrypted audit log data.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        cursor = connection.cursor()
        try:
            query = "SELECT LogID, UserID, Action, Description, Timestamp, IPAddress, BrowserInfo, SeverityLevel, Details FROM AuditLog"
            cursor.execute(query)
            logs = cursor.fetchall()

            decrypted_logs = []
            for log in logs:
                log_id, user_id, encrypted_action, encrypted_description, timestamp, encrypted_ip, encrypted_browser, severity_level, encrypted_details = log

                # Retrieve encryption key and nonce for x log entry
                key, nonce = self.pull_encryption_key(log_id)
                if key is None or nonce is None:
                    print(f"Cannot get the key or nonce for specified log ID {log_id}")
                    continue  # Skip ahead

                # Decrypt ze data
                # This could be problem:- error thrown if the return is none
                # therefore is setup to "skip" the decrypt process if none and just display none 
                action = decrypt_data(encrypted_action, key, nonce)
                description = decrypt_data(encrypted_description, key, nonce) if encrypted_description else None
                ip_address = decrypt_data(encrypted_ip, key, nonce) if encrypted_ip else None
                browser_info = decrypt_data(encrypted_browser, key, nonce) if encrypted_browser else None
                details = decrypt_data(encrypted_details, key, nonce) if encrypted_details else None

                decrypted_logs.append({
                    'LogID': log_id,
                    'UserID': user_id,
                    'Action': action,
                    'Description': description,
                    'Timestamp': timestamp,
                    'IPAddress': ip_address,
                    'BrowserInfo': browser_info,
                    'SeverityLevel': severity_level,
                    'Details': details
                })

            return decrypted_logs
        
        except Exception as e:
            print(f"Error fetching and decrypting audit log data: {str(e)}")
            return []
        finally:
            cursor.close()
            connection.close()
            
    def count_all_alog(self):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return 0

        cursor = connection.cursor()
        try:
            query = "SELECT COUNT(*) FROM AuditLog"
            cursor.execute(query)
            count = cursor.fetchone()[0]
            return count
        except Error as e:
            print(f"Error: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()
            
    def fetch_scan_data_by_owner(self, owner):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            connection.start_transaction()
            cursor = connection.cursor(prepared=True)
            query = """
            SELECT s.ScanID, s.Owner,
                   n.IPAddress, n.Hostname, n.Port, n.Protocol, n.ServiceName, n.ServiceVersion, n.State, n.OSFingerPrint, n.StartTime, n.EndTime, n.ScanType,
                   d.RecordType, d.RecordValue, d.Date, d.Domain,
                   v.Port, v.NVT, v.Description, v.Time, v.Type, v.HashValue, v.Severity,
                   z.Alert, z.URL, z.Risk, z.Detail, z.Timestamp, z.Rescan,
                   sp.URL AS SpiderURL, sp.StatusCode, sp.TimeStamp, sp.Method
            FROM Scans s
            LEFT JOIN NMAP n ON s.ScanID = n.ScanID
            LEFT JOIN DNS d ON s.ScanID = d.ScanID
            LEFT JOIN VAS v ON s.ScanID = v.ScanID
            LEFT JOIN ZAP z ON s.ScanID = z.ScanID
            LEFT JOIN Spider sp ON s.ScanID = sp.ScanID
            WHERE s.Owner = %s;
            """
            cursor.execute(query, (owner,))
            result = cursor.fetchall()
            connection.commit()  
            return result
        except Error as e:
                #connection.rollback()
                print(f"An error has occurred pulling scan details, Cancelled: {e}")

        finally:
                cursor.close()
                connection.close()