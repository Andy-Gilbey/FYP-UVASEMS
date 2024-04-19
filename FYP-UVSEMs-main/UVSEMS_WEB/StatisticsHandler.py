from datetime import datetime, timedelta

from EncryptionHandler import decrypt_data


class StatisticsHandler:
    def __init__(self,dbConnection):
        self.dbConnection = dbConnection
        
    def scans_in_week(self):
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor(prepared=True)
            # Calculate 7 days ago, not including today
            seven_days_ago = datetime.now() - timedelta(days=7)
            
            query = """
                SELECT COUNT(*) AS LastWeek
                FROM Scans
                WHERE ScanDate > %s
                AND ScanDate <= CURDATE()
            """
            cursor.execute(query, (seven_days_ago.date(),))
            result = cursor.fetchone()
            last_week_scans_count = result[0] if result else 0
            print(f"Number of scans in the last 7 days: {last_week_scans_count}")
            return last_week_scans_count
        except Exception as e:
            print(f"Database error: {e}")
            return 0
        finally:
            if cursor: cursor.close()
            if connection: connection.close()
            
            
    def get_scans_owner(self):
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor()
            query = """
                SELECT Owner, COUNT(*) as TotalScans
                FROM Scans
                GROUP BY Owner
            """
            cursor.execute(query)
            results = cursor.fetchall()
            scans_by_user = {row[0]: row[1] for row in results}
            return scans_by_user
        except Exception as e:
            print(f"Database error: {e}")
            return {}
        finally:
            cursor.close()
            connection.close()
            
 
            
            
    def get_all_scans_no(self):
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor()
            query = """
                SELECT COUNT(*) FROM Scans
            """
            cursor.execute(query)
            result = cursor.fetchone()  
            total_scans = result[0] if result else 0  
            return total_scans
        except Exception as e:
            print(f"Database error: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()
            
            
    def get_vas_sev_owner(self, owner_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        
        try:
            cursor = connection.cursor(dictionary=True)
            # This query should be adjusted based on your schema and requirements
            query = """
                    SELECT
                    CEIL(vr.Severity) as RoundedSeverity, COUNT(*) as Count
                    FROM
                    VAS_Results vr
                    JOIN
                    Scans s ON vr.ScanID = s.ScanID
                    WHERE
                    s.Owner = %s
                    GROUP BY
                    CEIL(vr.Severity);
                    """
            cursor.execute(query, (owner_id,))
            rows = cursor.fetchall()
            
            # Aggregate counts by severity
            severity_counts = {int(row['RoundedSeverity']): row['Count'] for row in rows}
            return severity_counts
        
        except Exception as e:
            print(f"Error counting vulnerabilities: {e}")
            return {}
        finally:
            cursor.close()
            connection.close()
                
                
    def get_zap_risk_owner(self, owner_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT
                    zr.Risk, COUNT(*) as Count
                    FROM
                    Zap_Results zr
                    JOIN
                    Scans s ON zr.ScanID = s.ScanID
                    WHERE
                    s.Owner = %s
                    GROUP BY
                    zr.Risk;
                    """
            cursor.execute(query, (owner_id,))
            rows = cursor.fetchall()
            
            # Aggregate those counts
            risk_counts = {row['Risk']: row['Count'] for row in rows}
            return risk_counts
        
        except Exception as e:
            print(f"Error counting ZAP vulnerabilities: {e}")
            return {}
        finally:
            cursor.close()  
            connection.close()  
            
    def get_count_tasks(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT COUNT(*) AS TotalCount
                    FROM Scans
                    WHERE AssignedAnalyst = %s;
                    """
            cursor.execute(query, (user_id,))
            res = cursor.fetchone()
            if res:
                    res = res['TotalCount']
                    return res
            else:
                print("Taks not found")
                return 0  
        except Exception as e:
                print(f"Error counting the tasks for user: {e}")
                return {}
        finally:
                cursor.close()  
                connection.close()
                
    def get_count_results(self):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT COUNT(*) AS TotalCount
                    FROM Reports;
                    """
            cursor.execute(query)
            res = cursor.fetchone()
            if res:
                    res = res['TotalCount']
                    return res
            else:
                print("Taks not found")
                return 0  
        except Exception as e:
                print(f"Error counting the reports: {e}")
                return {}
        finally:
                cursor.close()  
                connection.close()  
                
    def find_ana_besto(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT AssignedEngineer, COUNT(*) AS EngineerCount
                    FROM Scans
                    WHERE AssignedAnalyst = %s
                    GROUP BY AssignedEngineer
                    ORDER BY EngineerCount DESC
                    LIMIT 1;
                    """
            cursor.execute(query, (user_id,))
            res = cursor.fetchone()
            if res:
                    res = res['AssignedEngineer']
                    return res
            else:
                print("Friend not found. :-(")
                return 0  
        except Exception as e:
                print(f"Error finding friend: {e}")
                return {}
        finally:
                cursor.close()  
                connection.close()  
                
    def find_eng_besto(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return {}
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT AssignedAnalyst, COUNT(*) AS AnalystCount
                    FROM Scans
                    WHERE AssignedAnalyst = %s
                    GROUP BY AssignedEngineer
                    ORDER BY AnalystCount DESC
                    LIMIT 1;
                    """
            cursor.execute(query, (user_id,))
            res = cursor.fetchone()
            if res:
                    res = res['AssignedAnalyst']
                    return res
            else:
                print("Friend not found. :-(")
                return 0  
        except Exception as e:
                print(f"Error finding friend: {e}")
                return {}
        finally:
                cursor.close()  
                connection.close() 