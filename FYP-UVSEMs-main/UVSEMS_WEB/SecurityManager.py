import threading
from datetime import datetime, timedelta
from Audit import Audit

class SecurityManager:
    def __init__(self,dbConnection):
        self.failed_attempts = {}
        self.lock = threading.Lock()
        self.dbConnection = dbConnection
        self.auditer = Audit(dbConnection)


    def record_failed_login(self, username, ip_address, user_agent):
        """
        Used to record an invalid login attempt for x username. It increments a count of failed attempts
        and then updates a timestamp according to the last attempt. It then sends an audit log 

        Args:
        username(str): The username which was used for the invalid attempt.
        ip (str): The ip address from the attempt originated.
        user_agent (str): The user agent/browser details of the attemptS
        """
        with self.lock:
            attempts, _ = self.failed_attempts.get(username, (0, datetime.now()))
            attempts += 1
            self.failed_attempts[username] = (attempts, datetime.now())
            
            # I have setup variables here to pile into the audit log
            user_id = 0
            action = "Invalid Login Attempt"
            description = f"Failed login attempt for {username}"
            severity_level = 2
            category = "Authentication"
            details = f"IP: {ip_address}, Browser: {user_agent}"
            self.auditer.log_audit_entry(user_id, action, description, ip_address, user_agent, severity_level, category, details)

    def reset_failed_login(self, username):
        """
        Used to reset the count of the failed attempts. 
        
        Args:
        username (str): Username to reset the login attempts
        """
        with self.lock:
            if username in self.failed_attempts:
                del self.failed_attempts[username]

    def is_locked_out(self, username):
        """
        Checks if the given username is locked out due to going over the limit for login attempts within
        x timeframe.
        
        Args:
        username(str): Username to check
        
        Returns:
        bool: true if the user is locked out or false if not
        """
        with self.lock:
            if username in self.failed_attempts:
                attempts, last_attempt = self.failed_attempts[username]
                if attempts >= 3 and (datetime.now() - last_attempt) < timedelta(minutes=20):
                    return True
        return False
