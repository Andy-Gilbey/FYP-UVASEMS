import base64
import datetime
import json
import traceback
from typing import Self
import dns.resolver
from flask import render_template, session
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError
import xml.etree.ElementTree as ET
from mysql.connector import Error
from gvm.transforms import EtreeTransform
import requests
import sublist3r
import nmap
import psycopg2 # This is not great considering am already using sqlconnect but its only way to interact with GVM
import psycopg2.extras
from zapv2 import ZAPv2
import time

from EncryptionHandler import encrypt_data, generate_keynonce
from UserDataManager import UserDataManager  

class ScanUtils:
    def __init__(self, dbConnection):
        self.dbConnection = dbConnection
        self.userManager = UserDataManager(dbConnection) 

        
    
    
    @staticmethod
    def set_DNS_servers():
            """
            Function to make the code look some what cleaner going into the app-route.
            Used to set the DNS servers which will be used in conjunction with the DNS lookup.
            Principle idea is that this can be modified to alter the DNS servers being used for
            the scan or more servers can be added for a more in-depth scan.

            Returns:
                list: A list of DNS server addresses.
            """
            # Place holder, if I have time I can modify this to read in from a file
            # or have it so that a specific role probably pen-tester can alter the
            # dns servers that are in use or even the amount of servers used for the scan
            
            server_1 = "8.8.8.8" # Google
            server_2 = "1.1.1.1" # Cloud flare
            server_3 = "206.67.222.222" # OPEN DNS
            
            return [server_1,server_2,server_3]
    
    
    @staticmethod
    def do_DNS_scan(domain, servers):
        """
        v.12
        pulls DNS records for a given domain from multiple servers and 
        adds them into a dictionary with record types as keys. 
        A Records have their TTL and MX have mail exchange and priority included. 
        This is a similar formatting approch to MX Tools.com

        Args:
            domain (str): The domain name to query.
            servers (list): The list of DNS servers - this should be pulled from set_DNS_Servers function.

        Returns:
            dict: A dictionary utilising key pairs. THe key being the record_type
        """
        # Initialise the dictionary to store all DNS records.
        # Each record type (NS, A, TXT, MX) requires a specific list to store the records
        # Initialise the dictionary to store all DNS records with sets to avoid duplicates.
        dns_records = {'NS': set(), 'A': set(), 'TXT': set(), 'MX': set()}

        # Loop through each DNS server.
        for server in servers:
            # Configure a new resolver for each server in list
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 12
            resolver.lifetime = 12

            # Pull out the records for each type and add them to the sets in the dictionary.
            for record_type in dns_records.keys():
                try:
                    results = resolver.resolve(domain, record_type)
                    for result in results:
                        if record_type == 'A':
                            result_string = f"{result.address} (TTL: {results.rrset.ttl})"
                        elif record_type == 'MX':
                            result_string = f"{result.exchange} (Priority: {result.preference})"
                        else:
                            result_string = str(result)

                        dns_records[record_type].add(result_string)

                except Exception as e:
                    print(f"Error pulling {record_type} records from {server}: {e}")

        return {rtype: list(records) for rtype, records in dns_records.items()}




    @staticmethod
    def find_subdomains(domain):
        """
        **** 
        Subdomain enumeration, I am not overly sure of the of the unauthorised scanning for subdomains, Probably for 
        the best I discuss this Richard first.  I could use a robots.txt check before this scan takes place..."responsible practice" and
        all that. 
        ****
        
        Used to scan through a given domain and get a list of all their subdomains
        

        Args:
            domain (str): The inital domain to query

        Returns:
            sublist3r scan of the given domain
        """
        return sublist3r.main(domain,40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    
    def set_nmap_options(select):
        """
        v.2
        Retrieves Nmap command options based on a given int id for the scan type.

        This function will allow for the selection of predefined Nmap scan configurations
        using a specific identifier. It's designed for ease of use and adaptability- being that
        a developer can change/add options as they see fit.

        Args:
            scan_number (int): A number representing the type of Nmap scan. The function
                            maps numbers 1-7 to specific predefined scan types.

        Returns:
            str: A string of Nmap command options associated with the given number.
                If the number does not correspond to a predefined scan type,
                it returns an empty string for a default scan.
        """

        scan_options = {
            1: '-T4 -F',                      
            2: '-T4 -A -v',                   
            3: '-p 1-65535 -T4 -A -v',        
            4: '-T4 -A -v -Pn',               
            5: 'nmap -sS -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1', 
            6: '-sV -T4 -O -F --version-light',  
            7: ''                            
        }

        return scan_options.get(select, '')

        
    
    @staticmethod
    def doNmapScan(ip_address, scan_type):
        """
        Performs an Nmap scan on a given IP address using the predefined scan_type.

        Args:
            ip_address (str): The target IP address for the Nmap scan.
            scan_type (int): The ID for the type of Nmap scan to be performed.

        Returns:
            dict: A dictionary containing the scan results if successful, or an "unexpected error" message.
        """
        nm = nmap.PortScanner()
        scan_options = ScanUtils.set_nmap_options(scan_type)

        try:
            nm.scan(ip_address, arguments=scan_options)
            return nm[ip_address]
        except nmap.PortScannerError as e:
            return {"error": f"Nmap scan failed: {e}"}
        except Exception as e:
            return {"error": f"Unexpected error during Nmap scan: {e}"}


    def save_nmap_res(self, scan_id, nmapres, scan_type, start_time):
        """
        Encrypts and stores the Nmap scan results into the database.
        This method handles the encryption of individual data fields.
        """

        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to db at function level")
            return False

        cursor = connection.cursor(prepared=True)
        try:
            for port, data in nmapres.get('tcp', {}).items():
                ip_address = nmapres.get('addresses', {}).get('ipv4', 'N/A')
                hostname = nmapres.get('hostnames', [{'name': 'N/A'}])[0].get('name', 'N/A')
                os_fingerprint = ', '.join([os.get('name', 'N/A') for os in nmapres.get('osmatch', [])]) or 'N/A'


                key, nonce = generate_keynonce()
                encrypted_ip_address = encrypt_data(ip_address, key, nonce)
                encrypted_hostname = encrypt_data(hostname, key, nonce)
                encrypted_os_fingerprint = encrypt_data(os_fingerprint, key, nonce)
                
                key64 = base64.b64encode(key).decode('utf-8')
                nonce64 = base64.b64encode(nonce).decode('utf-8')

                insert_query = "INSERT INTO NmapResults (ScanID, IPAddress, Hostname, Port, Protocol, ServiceName, ServiceVersion, State, OSFingerPrint, StartTime, ScanType, EndTime) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())"
                cursor.execute(insert_query, (
                    scan_id,
                    encrypted_ip_address,
                    encrypted_hostname,
                    str(port),
                    encrypt_data(data.get('protocol', 'N/A'), key, nonce),
                    encrypt_data(data.get('name', 'N/A'), key, nonce),
                    encrypt_data(data.get('version', 'N/A'), key, nonce),
                    encrypt_data(data.get('state', 'N/A'), key, nonce),
                    encrypted_os_fingerprint,
                    start_time,
                    scan_type
                ))
                nmap_record_id = cursor.lastrowid
                connection.commit()

                if not self.save_nmap_encryption_key(nmap_record_id, key64, nonce64):
                    raise Exception("Failed to save encryption key and nonce at the function level")

            return True
        except Exception as e:
            print(f"Error in saving Nmap records: {e}")
            connection.rollback()
            return False
        finally:
            cursor.close()
            connection.close()

    def create_VAS_task(task_name, target_ip):
        # Setup the default port scanner list config and scanner id configs, the default can be modified
        # but I don't recommend changing these, This is primarily just to setup the task in vas
        # to corrolate it with a specific scan ID, no scanning is done by this function- just keep that in mind.
        default_port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
        default_scanner_id = "6acd0832-df90-11e4-b9d5-28d24461215b"

    ### #############
        socket_path = '/run/gvmd/gvmd.sock'
        openvas_username = 'admin'
        openvas_password = 'cfdf530c-c131-4eec-84b7-1115838c3564'
    ### #############


        # Initialise connection to GVMD first
        connection = UnixSocketConnection(path=socket_path)
        with Gmp(connection) as gmp:
            gmp.authenticate(openvas_username, openvas_password)  

            response = gmp.create_target(name=f"{task_name} Target", hosts=[target_ip], port_list_id=default_port_list_id)
            root_xml = ET.fromstring(response)
            target_id = root_xml.attrib.get('id')# Create the target
            if not target_id:
                raise Exception("Failed to create target") 

            ## Create the task
            response = gmp.create_task(name=task_name, config_id="daba56c8-73ec-11df-a475-002264764cea", target_id=target_id, scanner_id=default_scanner_id)
            root_xml = ET.fromstring(response)
            task_id = root_xml.attrib.get('id')
            if not task_id:
                raise Exception("Failed to create task")

            return task_id


    def start_VAS(self, task_id, port_list_id, scanner_id):
    ### #############
        socket_path = '/run/gvmd/gvmd.sock'
        openvas_username = 'admin'
        openvas_password = 'cfdf530c-c131-4eec-84b7-1115838c3564'
    ### #############
        connection = UnixSocketConnection(path=socket_path)
        with Gmp(connection) as gmp:
            gmp.authenticate(openvas_username, openvas_password)  # Authenticate GVM now

            gmp.modify_task(task_id=task_id, scanner_id=scanner_id)

            task_response = gmp.get_task(task_id)
        
            task_xml = ET.fromstring(task_response)
            target_id_element = task_xml.find('.//target')
            if target_id_element is not None:
                target_id = target_id_element.get('id')
                
                gmp.modify_target(target_id=target_id, port_list_id=port_list_id)
            else:
                raise ValueError("Target ID not found in task response.")

            # Start the task with the updated configs
            gmp.start_task(task_id)

            return f"Scan task started with task ID {task_id}"

    def snatch_VAS_reports():
    ### ####
        socket_path = '/run/gvmd/gvmd.sock' 
        openvas_username = 'admin'
        openvas_password = 'cfdf530c-c131-4eec-84b7-1115838c3564'
    ### ####

        reports = []
        # COnfigure the connection comm end point for IPC on this host machine - a way for the different
        # software processes to communicate with linux
        # This socket is used for secure communication with GVM CLI and the other GVM tools
        # THis for now is hardcoded above, will need to be changed down the line
        connection = UnixSocketConnection(path=socket_path)
        transform = EtreeTransform()
        # version = gml.get_version() <- picks up GMP version support by the remote daemon, commented out for now
        # pretty_print(version) <- This apparantly prints the xml in "beautiful form" DEBATABLE but will keep for future
        # should be noted the pretty_print will need importing from gvm.xml 
        
        try:
                with Gmp(connection) as gmp:
                    gmp.authenticate(openvas_username, openvas_password)
                    
                    tasks_xml = gmp.get_tasks()  # Get the XML for all tasks
                    tasks = transform(tasks_xml)  # Transform XML to something more workable

                    # loop through each task to get the last report
                    for task in tasks.findall('task'):
                        last_report = task.find('last_report/report')
                        
                        # only move on if there is a last report
                        if last_report is not None:
                            report_id = last_report.get('id')
                            
                            # get all the report details
                            report_xml = gmp.get_report(report_id)
                            report_tree = transform(report_xml)

                            # create a dictionary for each report
                            report = {
                                'date': report_tree.findtext('report/creation_time'),
                                'status': task.findtext('status'),
                                'task_name': task.findtext('name'),
                                'severity': report_tree.findtext('report/severity'),
                                'high': report_tree.findtext('report/result_count/high'),
                                'medium': report_tree.findtext('report/result_count/medium'),
                                'low': report_tree.findtext('report/result_count/low'),
                                'log': report_tree.findtext('report/result_count/log'),
                                'false_positive': report_tree.findtext('report/result_count/false_positive')
                            }

                            # append on the report dictionary to the reports list
                            reports.append(report)

                    # return the reports list after all tasks are processed
                    return reports

        except Exception as e:
                print(f"Error while fetching reports: {e}")
                return []  # return an empty in case of error
            
    def get_scans_by_user(self, user_id):
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor(prepared=True)
            query = 'SELECT ScanID, ScanName, Target, TaskID FROM Scans WHERE Owner = %s'
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()  
            scans_list = [{'ScanID': row[0], 'ScanName': row[1], 'Target': row[2],'TaskID': row[3]}  for row in results]
            print(scans_list)
            return scans_list
        except Exception as e:
            print(f"Database error: {e}")
            return [] 
        finally:
            cursor.close()
            connection.close()
                   
    def get_VAS_tasks(self,user_id):
        # First I need to get the list of Scans from Owner x
        scan_details = self.get_scans_by_user(user_id)
        scanIDs = [scan['ScanID'] for scan in scan_details] 
        task_ids = [scan['TaskID'] for scan in scan_details]
        tasks = []
        
        try:
                connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
                if connection is None:
                    print("Failed to connect to the PostgreSQL database.")
                    return []
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                for index, task_id in enumerate(task_ids):
                    query = """
                                SELECT 
                                id, name, run_status, start_time, end_time
                                FROM public.tasks
                                WHERE uuid = %s;
                            """
                    cursor.execute(query, (task_id,))
                    row = cursor.fetchone()  

                    if row:
                        start_time = datetime.datetime.fromtimestamp(int(row['start_time'])).strftime('%Y-%m-%d %H:%M:%S') if row['start_time'] is not None else 'N/A'
                        end_time = datetime.datetime.fromtimestamp(int(row['end_time'])).strftime('%Y-%m-%d %H:%M:%S') if row['end_time'] is not None else 'N/A'
                        scan_exists = self.check_scanID(scanIDs[index]) 
                        tasks.append({
                            'task_id': row['id'],
                            'name': row['name'],
                            'run_status': row['run_status'],
                            'start_time': start_time,
                            'end_time': end_time,
                            'scan_exists': scan_exists
                        })

                return tasks
            
        except psycopg2.DatabaseError as e:
                print(f"Task fetching error: {e}")
                return []
        finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()

    def snatch_CVES():
        try:

            ## Create a connection to vas db
            connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
            
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            query = """
                SELECT name, comment, description, creation_time, modification_time, cvss_vector, severity
                FROM scap.cves
                LIMIT 1000;  -- This limit is important, you can maximise it but.......risque
            """  
            cursor.execute(query)
            cve_details = cursor.fetchall()
            
            # Close the cursor and connection
            cursor.close()
            connection.close()
            
            for cve in cve_details:
                # Convert Unix timestamps to datetime objects so it works
                cve['creation_time'] = datetime.datetime.fromtimestamp(cve['creation_time'])
                cve['modification_time'] = datetime.datetime.fromtimestamp(cve['modification_time'])

            return cve_details
        
        except Exception as e:
            print(f"Error snatching the NVTs: {e}")
            return []
        
    def count_CVES():
        try:
            ## Create a connection to gvmd database
            connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            query = """
                SELECT severity, COUNT(*) as count
                FROM scap.cves
                GROUP BY severity
            """
            cursor.execute(query)
            cve_counts = cursor.fetchall()
            cursor.close()
            connection.close()

            return cve_counts

        except Exception as e:
            print("Error counting NVTs:", e)
            
    def snatch_CVES_by_time():
            try:
                    connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
                    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                    query = """
                            SELECT period, COUNT(*) as count
                            FROM (
                                SELECT 
                                    CASE 
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '1 day' THEN 'Since Yesterday'
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '7 days' THEN 'Last 7 Days'
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '30 days' THEN 'Last 30 Days'
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '92 days' THEN 'Last 92 Days'
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '12 months' THEN 'Last 12 Months'
                                        WHEN to_timestamp(creation_time) >= CURRENT_DATE - INTERVAL '5 years' THEN 'Last 5 Years'
                                        ELSE 'Older'
                                    END AS period
                                FROM scap.cves
                            ) AS sub
                            GROUP BY period
                            ORDER BY 
                                CASE period
                                    WHEN 'Since Yesterday' THEN 1
                                    WHEN 'Last 7 Days' THEN 2
                                    WHEN 'Last 30 Days' THEN 3
                                    WHEN 'Last 92 Days' THEN 4
                                    WHEN 'Last 12 Months' THEN 5
                                    WHEN 'Last 5 Years' THEN 6
                                    ELSE 7
                                END
                            """
                    

                    cursor.execute(query)
                    cve_counts = cursor.fetchall()
                    cursor.close()
                    connection.close()

                    return cve_counts

            except Exception as e:
                    print("Error in the mod time snatching:", e)
                    return []

    def snatch_CVES_by_year():
            try:
                    connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
                    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                    query = """
                        SELECT EXTRACT(YEAR FROM to_timestamp(creation_time)) AS year, COUNT(*) AS total_cves
                        FROM scap.cves
                        GROUP BY year
                        ORDER BY year;
                            """

                    cursor.execute(query)
                    cve_by_years = cursor.fetchall()
                    cursor.close()
                    connection.close()

                    return cve_by_years

            except Exception as e:
                    print("Error in the mod time snatching:", e)
                    return []

    def snatch_nmap_encryption_key(self, nmapRecordID):
        """
        Pulls an associated encryption key and nonce from the KeyBank database which is linked to an Nmap results ID.

        This function connects to the KeyBank db and retrieves the encryption key and nonce for the given Nmap record ID.

        Args:
            nmapRecordID (int): The Nmap record ID whose encryption key and nonce are to be fetched.

        Returns:
            tuple: A tuple containing the encryption key and nonce if found if not returns (None, None).
        """
        
        connection = self.dbConnection.createKeyBankConnection()
        if connection is None:
            print("Failed to connect to the KeyBank database")
            return None, None

        cursor = connection.cursor()
        try:
            query = "SELECT `NmapResKey`, `NmapResNonce` FROM NmapBank WHERE NmapResID = %s"
            cursor.execute(query, (nmapRecordID,))
            result = cursor.fetchone()

            if result:
                key, nonce = result
                key = base64.b64decode(key)
                nonce = base64.b64decode(nonce)
                # print(f"NmapResID: {nmap_res_id}, NmapResKey: {key}, NmapResNonce: {nonce}")  # Debugging 
                return key, nonce
            else:
                print(f"NmapResID {nmapRecordID} not found in the NmapResults database.")
                return None, None
        except Exception as e:
            print(f"Error retrieving encryption key and nonce: {traceback.format_exc()}") # Need full traceback this function killed me
            return None, None
        finally:
            cursor.close()
            connection.close()
    def snatch_dns_encryption_key(self, dns_record_id):
        """
        Pulls an associated encryption key and nonce from the KeyBank database which is linked to a DNS record ID.

        This function connects to the KeyBank db and retrieves the encryption key and nonce for the given DNS record ID.

        Args:
            dns_record_id (int): The DNS record ID whose encryption key and nonce are to be fetched.

        Returns:
            tuple: A tuple containing the encryption key and nonce if found, otherwise (None, None).
        """
        connection = self.dbConnection.createKeyBankConnection()
        if connection is None:
            print("Failed to connect to the KeyBank database")
            return None, None

        cursor = connection.cursor()
        try:
            query = "SELECT `DNSRecordKey`, `DNSRecordNonce` FROM DNSBank WHERE DNSRecordID = %s"
            cursor.execute(query, (dns_record_id,))
            result = cursor.fetchone()

            if result:
                key, nonce = result
                key = base64.b64decode(key)
                nonce = base64.b64decode(nonce)
                # print(f"DnsResID: {dns_record_id}, DnsResKey: {key}, DnsResNonce: {nonce}")  # Debugging Diagnostic
                return key, nonce
            else:
                print(f"DnsResID {dns_record_id} not found in the DNSBank database.")
                return None, None
        except Exception as e:
            print(f"Error retrieving encryption key and nonce: {traceback.format_exc()}") # Need full traceback this function killed me
            return None, None
        finally:
            cursor.close()
            connection.close()        
  
    def save_dns_encryption_key(self, dnsRecordId, key, nonce):
        """
        Saves an encryption key and nonce in the KeyBank database associated with a specific DNS record ID.

        This method connects to the KeyBank db and inserts the provided encryption key and nonce into the DNSKeyBank table, associated with the provided DNS record ID.

        Args:
            dnsRecordId (int): The DNS record ID that is associated with the encryption key.
            key (str): The encryption key to be saved.
            nonce (str): The nonce to be saved.

        Returns:
            bool: True if the key and nonce are successfully saved, otherwise False.
        """
        
        keybank_connection = self.dbConnection.createKeyBankConnection()
        if keybank_connection is None:
            print("Failed to connect to the KeyBank database")
            return False

        cursor = keybank_connection.cursor()
        try:
            insertKeyAndNonceQuery = "INSERT INTO DNSBank (DNSRecordID, `DNSRecordKey`, DNSRecordNonce) VALUES (%s, %s, %s)"
            cursor.execute(insertKeyAndNonceQuery, (dnsRecordId, key, nonce))
            keybank_connection.commit()
        except Error as e:
            print(f"Error saving DNS encryption key and nonce: {e}")
            keybank_connection.rollback()
            return False
        finally:
            cursor.close()
            keybank_connection.close()

        return True
    
    def save_nmap_encryption_key(self, nmapRecordID, key, nonce):
        """
        Saves an encryption key and nonce in the KeyBank database associated with a specific Nmap results ID.

        This method connects to the KeyBank db and inserts the provided encryption key and nonce into the Key database.

        Args:
            nmapRecordID (int): The Nmap record ID that is associated with the encryption key.
            key (str): The encryption key to be saved.
            nonce (str): The nonce to be saved.

        Returns:
            bool: True if the key and nonce are successfully saved, otherwise False.
        """
        
        keybank_connection = self.dbConnection.createKeyBankConnection()
        if keybank_connection is None:
            print("Failed to connect to the KeyBank database")
            return False

        cursor = keybank_connection.cursor()
        try:
            insertKeyAndNonceQuery = "INSERT INTO NmapBank (NmapResID, `NmapResKey`, NmapResNonce) VALUES (%s, %s, %s)"
            cursor.execute(insertKeyAndNonceQuery, (nmapRecordID, key, nonce))
            keybank_connection.commit()
        except Error as e:
            print(f"Error saving DNS encryption key and nonce: {e}")
            keybank_connection.rollback()
            return False
        finally:
            cursor.close()
            keybank_connection.close()

        return True

    
    
    def save_dns_records(self,scanID, domain, dns_records):
        """
            v.8
            Encrypts and stores the DNS records post-scan into the database.
            This handles the encryption for all DNS records.
            It should be noted that the corresponding list of records are concatenated into a single
            string, using ## as a delimiter. This concatenation is employed in order to optimise the storage
            space inside the database. The delimiter is used to facilitate easy retrieval and decryption.
            
            Args:
                domain (str): The domain name associated with the DNS records.
                dns_records (dict): the dictionary of DNS records, where keys are record types.

            Returns:
                bool: True if all records are successfully added to the database, otherwise False.
            """
        
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to db at function level")
            return False
        
        cursor = connection.cursor(prepared=True)
        try:
            for record_type, records in dns_records.items():
                # Concatenate records into a single string
                # Uses ## as a delimiter
                concat_records = '##'.join(records)
                # Encrypt the concatenated records
                key, nonce = generate_keynonce()
                encrypted_concat_records = encrypt_data(concat_records, key, nonce)
                # encrypted_record_type = encrypt_data(record_type, key, nonce)
                
                key64 = base64.b64encode(key).decode('utf-8')
                nonce64 = base64.b64encode(nonce).decode('utf-8')
                
                # Insert the encrypted records into the database
                query = "INSERT INTO DNSRecords (ScanID, Domain, RecordType, RecordValue, Date) VALUES (%s, %s, %s, %s, NOW())"
                cursor.execute(query, (scanID, domain, record_type, encrypted_concat_records))
                dns_record_id = cursor.lastrowid
                connection.commit()      
                
                if not self.save_dns_encryption_key(dns_record_id, key64, nonce64):
                    raise Exception("Failed to save encryption key and nonce at the function level")
            return True
        except Exception as e:
                print(f"Error in saving DNS records: {e}")
                connection.rollback()
                return False
        finally:
            cursor.close()
            connection.close()
            
    def create_new_scan(self,scan_name, target, task_id, user_id, retestOf):
        """
        v.05 {Added Status}
        Inserts a new scan record into the Scans table

        Args:
            scan_name (str): The name of the scan, a personal identifier for the task, can be anything.
            target (str): The target of the scan, this is an IP usually.
            task_id (str): The task ID from OpenVAS, this is required to link back to a VAS scan.
            user_id (int): The User ID Pulled from the session, this is required to link the scan to a user

        Returns:
            int: The generated ScanID of the new scan record, or None if insertion fails.
        """
        status = "Initiated" # Last var to throw in to start lifecycle of scan
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to db at function level")
            return None

        cursor = connection.cursor()
        try:
            query = "INSERT INTO Scans (ScanName, Target, ScanDate, TaskID, Owner,RetestOf, Status) VALUES (%s, %s, NOW(), %s, %s, %s, %s )"
            cursor.execute(query, (scan_name, target, task_id,user_id,retestOf,status))
            connection.commit()

            scan_id = cursor.lastrowid
            return scan_id

        except Exception as e:
            print(f"Error creating new scan: {e}")
            connection.rollback()
            return None

        finally:
            cursor.close()
            connection.close()

    def process_scan_to_database(self,scan_name):
        """
        Fetches Task ID based on scan_name, retrieves and parses OpenVAS report,
        then inserts report details into the database.
        
        Args:
            scan_name (str): The name of the scan to process.
        
        Returns:
            bool: True if successful, False otherwise.
        """
        # Step 1: Fetch Task ID from Database
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor(prepared=True)
            query = "SELECT TaskID, ScanID FROM Scans WHERE ScanName = %s"
            cursor.execute(query, (scan_name,))
            result = cursor.fetchone()
            if not result:
                print("Scan name not found in database.")
                return False
            uuid = result[0]
            scan_id = result[1]  
        except Exception as e:
            print(f"Database query error: {e}")
            return False
        finally:
            cursor.close()
        
        try:
        # Check if its already gone to DB
        ## Create a connection to gvmd database
            connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            query = """
                        SELECT id
                        FROM public.tasks
                        WHERE uuid = %s;
                    """
            cursor.execute(query, (uuid,))
            result = cursor.fetchone()
                    
            if result:
                task_id = result['id']  # ID will be the first one
            else:
                task_id = 0
                
        except psycopg2.DatabaseError as e:
            print(f"PYSCOPG2- Database error: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection:
                cursor.close()

            try:
                connection = psycopg2.connect(dbname="gvmd", user="superuser", password="pass")
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                query = """
                            SELECT 
                            host,
                            port,
                            nvt,  
                            result_nvt,
                            type,
                            description,
                            severity,
                            qod,
                            qod_type,
                            owner,
                            date,
                            hostname,
                            path,
                            hash_value
                            FROM public.results
                            WHERE task = %s;
                        """
                cursor.execute(query, (task_id,))
                rows = cursor.fetchall()
                details = []
                for row in rows:
                    details.append({
                        'host': row['host'],
                        'port': row['port'],
                        'nvt': row['nvt'],
                        'result_nvt': row['result_nvt'],
                        'type': row['type'],
                        'description': row['description'],
                        'severity': row['severity'],
                        'qod': row['qod'],
                        'qod_type': row['qod_type'],
                        'owner': row['owner'],
                        'date': row['date'],
                        'hostname': row['hostname'],
                        'path': row['path'],
                        'hash_value': row['hash_value']
                    })
                    
                    # DEBUG REMOVE LATER
                    #for detail in details:
                    #    print(detail)
                        
            except psycopg2.DatabaseError as e:
                print(f"Vulnerability fetching error;: {e}")
                return None
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    cursor.close()
                    
        connection = self.dbConnection.createConnection()            
        if connection is None:
            print("Failed to connect to db at function level")
            return False

        try:
            cursor = connection.cursor(prepared=True)
            query = """
                    INSERT INTO VAS_Results 
                    (ScanID, Port, NVT, Description, Time, Type, HashValue, Severity)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """

            for detail in details:
                time = datetime.datetime.fromtimestamp(int(detail['date']))

                data = (
                    scan_id,
                    detail['port'],
                    detail['nvt'],  
                    detail['description'],
                    time,
                    detail['type'],
                    detail['hash_value'],
                    detail['severity'],
                )

                cursor.execute(query, data)

            connection.commit()
            print("Successfully inserted details into VAS_Results.")
            return True
        except Error as e:
            print(f"Error inserting into database: {e}")
            connection.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
 

    def check_scan_already(self,scan_name):
        """
            Only one Scan of Scan Name x can exist. This function is used to check if
            "scan_name" is in the database. Used BEFORE the function that creates a new scan.
            
        Args:
            scan_name (str): The name of the scan to be looked at.
        
        Returns:
            bool: True if exists, False if does not.
        """
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor(prepared=True)
            query = 'SELECT 1 FROM Scans WHERE ScanName = %s LIMIT 1'
            cursor.execute(query ,(scan_name,))
            result = cursor.fetchone()
            return bool(result)
        except Exception as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
            
    def check_scanID(self,scan_id):
        """
            When sending a VAS report to the database, there should only be one.
            So no two vas results can contain the same SCANID (this would be the same result)
            This function checks to see if the Scan ID already exists.
            
        Args:
            scan_id (int): The ID of the scan being checked.
        
        Returns:
            bool: True if exists or False if does not.
        """
        connection = self.dbConnection.createConnection()
        try:
            cursor = connection.cursor(prepared=True)
            query = 'SELECT 1 FROM VAS_Results WHERE ScanID = %s LIMIT 1'
            cursor.execute(query, (scan_id,))
            result = cursor.fetchone()
            return bool(result)
        except Exception as e:
            print(f"Database error: {e}")
            return False
        finally:
            cursor.close()
            connection.close()      
            
            
   
        
    def run_zap_scan(self,scan_target, zap_scan_type, use_crawler, exclusion_list, scanID, userID):
        spider_result_ids = None
        try:
            zap = ZAPv2(apikey='bpcvbfh9imout5rheegkmbjvn9', proxies={'http': 'http://127.0.0.1:8080'})
            api_key = 'bpcvbfh9imout5rheegkmbjvn9'
            session_name = f"scan_session_{scanID}" 
            zap.core.new_session(name=session_name, overwrite=True)
            print(f"New ZAP session created: {session_name}")
            
            # Configure all exclusions frm list
            for url in exclusion_list:
                zap.spider.exclude_from_scan(url)
                zap.ascan.exclude_from_scan(url)
            
            # Run the spider if requested
            if use_crawler:
                spider_scan_id = zap.spider.scan(scan_target)
                print(f"Spider scan initiated with ID: {spider_scan_id}")
                while int(zap.spider.status(spider_scan_id)) < 100:
                    print("Spider progress %: {}".format(zap.spider.status(spider_scan_id)))
                    time.sleep(2)  # pause the execution for 2 seconds between checks

                print("Spider scan completed.")
                spider_result_ids = zap.spider.results(spider_scan_id)  
                print(f"Spider found the following URLs: {spider_result_ids}")
                response = requests.get(f'http://127.0.0.1:8080/JSON/core/view/messages/?apikey={api_key}')
                organized_data = {} 
                # check if request was successful
                if response.status_code == 200:
                    data = response.json()

                    for message in data['messages']:
                        method = message['requestHeader'].split(' ')[0]
                        status_code = message['responseHeader'].split(' ')[1]
                        timestamp = datetime.datetime.fromtimestamp(int(message['timestamp'])/1000).strftime('%Y-%m-%d %H:%M:%S')
                        user_agent = next((line.split(': ')[1] for line in message['requestHeader'].split('\n') if 'User-Agent' in line), 'Unknown')
                        url = message['requestHeader'].split(' ')[1]

                        if url not in organized_data:
                            organized_data[url] = []
                        organized_data[url].append({
                            'method': method,
                            'status_code': status_code,
                            'timestamp': timestamp,
                            'user_agent': user_agent,
                        })
                else:
                    print(f"Failed to fetch data, status code: {response.status_code}")            

      ###############      
            if zap_scan_type == "2":  # Active scan
                scan_id = zap.ascan.scan(scan_target)
                if scan_id and scan_id != 'url_not_found':  
                    print(f"Active scan initiated with ID: {scan_id}")
                    while int(zap.ascan.status(scan_id)) < 100:
                        time.sleep(5)  # pause execution for 5 seconds between thd checks
                    print("Active scan completed using policy:")
                else:
                    print("Failed to initiate active scan. Scan target URL not found.")
            else:
                print("Invalid scan type specified.")

            print("Scan completed for target: {}".format(scan_target))
            alerts = zap.core.alerts(baseurl=scan_target)
            num_alerts = len(alerts)
            print("Number of alerts detected:", num_alerts)
            print(f"Scan completed for target: {scan_target}. Number of alerts detected: {len(alerts)}")
            
            saved_alerts = ScanUtils.alert_handler(alerts)
            self.save_zap_results(saved_alerts,scanID,userID, organized_data)
            
            ## Start the alerts fresh
            zap.core.delete_all_alerts()
            print("Alerts Recieved and now cleared.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            
            
    def save_zap_results(self, alerts, ScanID, userID, organized_data):
        """
        This function stores ZAP scan results into the database.

        Args:
            scan_results (list of dicts): A list where each dict contains the details of a single alert.
                                        Each dict has keys: 'ScanID', 'Owner', 'Alert', 'URL', 'Risk', 'Detail'

        Returns:
            bool: True if all results are successfully added to the database; otherwise, False.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return False

        cursor = connection.cursor(prepared=True)
        try:
            insertScanResultQuery = "INSERT INTO Zap_Results (ScanID, Owner, Timestamp, Alert, URL, Risk, Detail) VALUES (%s, %s, NOW(), %s, %s, %s, %s)"
            insertSpiderQuery = "INSERT INTO Spider (URL, ScanID, StatusCode, TimeStamp, Method) VALUES (%s, %s, %s, %s, %s)"
            
            for alert in alerts:
                cursor.execute(
                    insertScanResultQuery,
                    (
                        ScanID,
                        userID,
                        alert["Alert"],
                        alert["URL"],
                        alert["Risk"],
                        alert["Detail"]
                    ),
                )
            
            for url, messages in organized_data.items():
                for message in messages:
                    cursor.execute(
                        insertSpiderQuery,
                        (
                            url, 
                            ScanID,  
                            message['status_code'],  
                            message['timestamp'],  
                            message['method'],  
                        ),
                    )
            connection.commit()
            return True
        except Error as e:
            print(f"Error in Saving the ZAP results: {e}")
            connection.rollback()
            return False
        finally:
            cursor.close()
            connection.close()
    
    def alert_handler(alerts):
        seen = set()
        alerts_return = []
        for alert in alerts:
            identifier = (alert.get('alert'), alert.get('url'), alert.get('risk'), alert.get('description'))
            if identifier not in seen:
                seen.add(identifier)
                alerts_return.append({
                    'Alert': alert.get('alert'),
                    'URL': alert.get('url'),
                    'Risk': alert.get('risk'),
                    'Detail': alert.get('description')
                })
        return alerts_return
    
    def snatch_my_scans(self, owner):
            """
            Gets all the scans with specific indiciators for DNS,VAS,ZAP And NAMP to determine whcih scans
            were actually carried out in conjunction with whatever scan is under query.
            
            Args:
                owner (int): The owner of the scans to be fetched.
            
            Returns:
                list of dict: A list where each dict contains details of a scan and boolean indicators for related records.
            """
            connection = self.dbConnection.createConnection()
            if connection is None:
                print("Failed to connect to the database")
                return []
            scans = []
            try:
                cursor = connection.cursor()
                query = """ 
                        SELECT 
                            s.ScanID,
                            s.ScanName,
                            s.Target,
                            s.ScanDate,
                            EXISTS (SELECT 1 FROM NmapResults nm WHERE nm.ScanID = s.ScanID) AS NMap,
                            EXISTS (SELECT 1 FROM DNSRecords dns WHERE dns.ScanID = s.ScanID) AS DNS,
                            EXISTS (SELECT 1 FROM VAS_Results vas WHERE vas.ScanID = s.ScanID) AS VAS,
                            EXISTS (SELECT 1 FROM Zap_Results zap WHERE zap.ScanID = s.ScanID) AS ZAP
                        FROM 
                            Scans s
                        WHERE 
                            s.Owner = %s
                """
                cursor.execute(query, (owner,))
                rows = cursor.fetchall()

                for row in rows:
                    scans.append({
                        'ScanID': row[0],
                        'ScanName': row[1],
                        'Target': row[2],
                        'ScanDate': row[3],
                        'NMap': row[4],
                        'DNS': row[5],
                        'VAS': row[6],
                        'ZAP': row[7]
                    })
            except Exception as e:
                print(f"Database error: {e}")
                return []
            finally:
                cursor.close()
                connection.close()
            return scans
         
    def count_all_scan_types(self, owner_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return 0, 0, 0, 0  # NMAP, DNS, VAS, ZAP
        
        try:
            cursor = connection.cursor(dictionary=True)
            query = """
                    SELECT 
                        EXISTS (SELECT 1 FROM NmapResults nm WHERE nm.ScanID = s.ScanID) AS NMap,
                        EXISTS (SELECT 1 FROM DNSRecords dns WHERE dns.ScanID = s.ScanID) AS DNS,
                        EXISTS (SELECT 1 FROM VAS_Results vas WHERE vas.ScanID = s.ScanID) AS VAS,
                        EXISTS (SELECT 1 FROM Zap_Results zap WHERE zap.ScanID = s.ScanID) AS ZAP
                    FROM 
                        Scans s
                    WHERE 
                        s.Owner = %s
            """
            cursor.execute(query, (owner_id,))
            rows = cursor.fetchall()
            

            nmap_count = 0
            dns_count = 0
            vas_count = 0
            zap_count = 0
            
            for row in rows:
                if row['NMap']:  # For NMap
                    nmap_count += 1
                if row['DNS']:  # For DNS
                    dns_count += 1
                if row['VAS']:  # For VAS
                    vas_count += 1
                if row['ZAP']:  # For ZAP
                    zap_count += 1

        except Exception as e:
            print(f"Database error: {e}")
            return 0, 0, 0, 0
        finally:
            cursor.close()
            connection.close()
        
        return nmap_count, dns_count, vas_count, zap_count
    
    
    
    def snatch_scannames_by_id(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []
        try:
            cursor = connection.cursor(prepared=True)
            query = """
                    SELECT ScanID, ScanName FROM Scans WHERE Owner = %s;
                    """
            cursor.execute(query, (user_id,))
            rows = cursor.fetchall()
            return rows
        except Exception as e:
            print(f"Error getting the scans: {e}")
            return []
        finally:
            cursor.close
            connection.close
    
    
    ## I did created this function late in development...It would have saved me some time to just get this out straight away
    def get_scan(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []
        try:
            cursor = connection.cursor(dictionary=True)  
            query = """
                    SELECT ScanID, ScanName, Target, ScanDate, Owner, AssignedAnalyst, 
                    AssignedEngineer, RetestOf, Priority, Status, Close_Date
                    FROM Scans WHERE ScanID = %s;
                    """
            cursor.execute(query, (scan_id,))
            rows = cursor.fetchall()
            return rows
        except Exception as e:
            print(f"Error getting the scans: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
            
    def get_retests(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []
        try:
            cursor = connection.cursor(dictionary=True)  
            query = """
                    SELECT ScanID, ScanName, Target, ScanDate, TaskID, Owner, AssignedAnalyst, AssignedEngineer, RetestOf, Priority, Status, Close_Date
                    FROM Scans
                    WHERE Owner = %s AND Status = 'Retest Required'
                """
            cursor.execute(query, (user_id,))
            rows = cursor.fetchall()
            return rows
        except Exception as e:
            print(f"Error getting the scans: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
            
            
    def get_retests_count(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []
        try:
            cursor = connection.cursor(dictionary=True)  
            query = """
                    SELECT COUNT(*) AS RetestCount
                    FROM Scans
                    WHERE Owner = %s AND Status = 'Retest Required'
                """
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            return result['RetestCount'] if result else 0
        except Exception as e:
            print(f"Error getting the scans: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()
        
        
    def snatch_scans_via_id(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True, dictionary=True)  
            query = """
                    SELECT s.ScanID, s.Owner,
                        nr.IPAddress, nr.Hostname, nr.Port, nr.Protocol, nr.ServiceName, nr.ServiceVersion, nr.State, nr.OSFingerPrint, nr.StartTime, nr.EndTime, nr.ScanType,
                        dr.RecordType, dr.RecordValue, dr.Date, dr.Domain,
                        vr.Port, vr.NVT, vr.Description, vr.Time, vr.Type, vr.HashValue, vr.Severity,
                        zr.Alert, zr.URL, zr.Risk, zr.Detail, zr.Timestamp, zr.Rescan,
                        sp.URL AS SpiderURL, sp.StatusCode, sp.TimeStamp, sp.Method
                    FROM Scans s
                    LEFT JOIN NmapResults nr ON s.ScanID = nr.ScanID
                    LEFT JOIN DNSRecords dr ON s.ScanID = dr.ScanID
                    LEFT JOIN VAS_Results vr ON s.ScanID = vr.ScanID
                    LEFT JOIN Zap_Results zr ON s.ScanID = zr.ScanID
                    LEFT JOIN Spider sp ON s.ScanID = sp.ScanID
                    WHERE s.ScanID = %s;
                    """
            cursor.execute(query, (scan_id,))
            rows = cursor.fetchall()
            connection.commit()  
            

            scans_list = []
            for row in rows:
                scan_data = {
                    "ScanID": row["ScanID"],
                    "Owner": row["Owner"],
                    "NMAP": {
                        "IPAddress": row["IPAddress"],
                        "Hostname": row["Hostname"],
                        "Port": row["Port"],
                        "Protocol": row["Protocol"],
                        "ServiceName": row["ServiceName"],
                        "ServiceVersion": row["ServiceVersion"],
                        "State": row["State"],
                        "OSFingerPrint": row["OSFingerPrint"],
                        "StartTime": row["StartTime"],
                        "EndTime": row["EndTime"],
                        "ScanType": row["ScanType"]
                    },
                    "DNS": {
                        "RecordType": row["RecordType"],
                        "RecordValue": row["RecordValue"],
                        "Date": row["Date"],
                        "Domain": row["Domain"]
                    },
                    "VAS": {
                        "Port": row["Port"],
                        "NVT": row["NVT"],
                        "Description": row["Description"],
                        "Time": row["Time"],
                        "Type": row["Type"],
                        "HashValue": row["HashValue"],
                        "Severity": row["Severity"]
                    },
                    "ZAP": {
                        "Alert": row["Alert"],
                        "URL": row["URL"],
                        "Risk": row["Risk"],
                        "Detail": row["Detail"],
                        "Timestamp": row["Timestamp"],
                        "Rescan": row["Rescan"]
                    },
                    "Spider": {
                        "URL": row["SpiderURL"],
                        "StatusCode": row["StatusCode"],
                        "TimeStamp": row["TimeStamp"],
                        "Method": row["Method"]
                    }
                }
                scans_list.append(scan_data)
            return scans_list
        
        except Exception as e:
            print(f"Database Pull error in picking the scan results {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                

    def populate_ana_scans(self,user_id):
        """
        Fetches scans associated with the given user ID, including AnaNotes and AnaNotesTimestamp.
        Returns a list of dictionaries with selected fields.
        """

        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(dictionary=True)
            query = """
                SELECT Scans.ScanID, Scans.ScanName, Scans.Target, Scans.ScanDate, Scans.Priority, Scans.Status,
                    Scans.AssignedEngineer,ScanNotes.AnaNotes, ScanNotes.AnaNotesTimestamp, ScanNotes.EngNotes, 
                    ScanNotes.EngNotesTimeStamp
                FROM Scans
                LEFT JOIN ScanNotes ON Scans.ScanID = ScanNotes.ScanID
                WHERE Scans.AssignedAnalyst = %s
            """
            cursor.execute(query, (user_id,))
            scans = cursor.fetchall()
            
            ## Need to swap the int for the engineer to their username
            for scan in scans:
                engineer_user_id = scan['AssignedEngineer']
                engineer_username = self.userManager.get_username(engineer_user_id)
                scan['AssignedEngineer'] = engineer_username  
            
            return scans
        except Exception as e:
            print(f"Error getting the scans for analyst page: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
    def populate_eng_scans(self,user_id):
            """
            Fetches scans associated with the given user ID, including ENgNotes and ENgNotesTimestamp.
            Returns a list of dictionaries with selected fields.
            """

            connection = None
            cursor = None
            try:
                connection = self.dbConnection.createConnection()
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT Scans.ScanID, Scans.ScanName, Scans.Target, Scans.ScanDate, Scans.Priority, Scans.Status,
                        Scans.AssignedEngineer,Scans.AssignedAnalyst,ScanNotes.AnaNotes, ScanNotes.AnaNotesTimestamp, ScanNotes.EngNotes, 
                        ScanNotes.EngNotesTimeStamp
                    FROM Scans
                    LEFT JOIN ScanNotes ON Scans.ScanID = ScanNotes.ScanID
                    WHERE Scans.AssignedEngineer = %s
                """
                cursor.execute(query, (user_id,))
                scans = cursor.fetchall()
                
                ## Need to swap the int for the engineer to their username
                for scan in scans:
                    analyst_user_id = scan['AssignedAnalyst']
                    analyst_username = self.userManager.get_username(analyst_user_id)
                    scan['AssignedAnalyst'] = analyst_username  
                
                return scans
            except Exception as e:
                print(f"Error getting the scans for eng page: {e}")
                return []
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()
                
    def ana_update_notes(self, scan_id, notes):
        connection = None
        cursor = None
        # Debug 
        print("THIS HAS LANDED")
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)

            # construct the note with timestamp
            timestamp = datetime.datetime.now().strftime("%d/%m/%y %H:%M")
            updated_notes = f"[{timestamp}]: {notes}"

            # get all existing notes
            select_query = "SELECT AnaNotes FROM ScanNotes WHERE ScanID = %s"
            cursor.execute(select_query, (scan_id,))
            existing_notes = cursor.fetchone()

            # concat old and new notes
            if existing_notes and existing_notes[0]:
                updated_notes = existing_notes[0] + "\n" + updated_notes

            update_query = """
                UPDATE ScanNotes
                SET AnaNotes = %s,
                AnaNotesTimestamp = NOW()
                WHERE ScanID = %s
            """
            cursor.execute(update_query, (updated_notes, scan_id))
            connection.commit()
            return True 
        except Exception as e:
            print(f"Error updating notes: {e}")
            if connection:
                connection.rollback()
            return False  
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
                
    def eng_update_notes(self, scan_id, notes):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)

            # make a note; add the time stamp first then note
            # so TIMESTAMP:Note 
            timestamp = datetime.datetime.now().strftime("%d/%m/%y %H:%M")
            updated_notes = f"[{timestamp}]: {notes}"


            select_query = "SELECT EngNotes FROM ScanNotes WHERE ScanID = %s"
            cursor.execute(select_query, (scan_id,))
            existing_notes = cursor.fetchone()

            # Gotta combine the notes to the old notes
            if existing_notes and existing_notes[0]:
                updated_notes = existing_notes[0] + "\n" + updated_notes

            update_query = """
                UPDATE ScanNotes
                SET EngNotes = %s,
                EngNotesTimeStamp = NOW()
                WHERE ScanID = %s
            """
            cursor.execute(update_query, (updated_notes, scan_id))
            connection.commit()
            return True 
        except Exception as e:
            print(f"Error updating notes: {e}")
            if connection:
                connection.rollback()
            return False  
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
    def ana_update_status(self,scan_id, pri):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            update_query = """
                UPDATE Scans
                SET Priority = %s
                WHERE ScanID = %s
            """
            cursor.execute(update_query, (pri, scan_id))
            connection.commit()
            return True 
        except Exception as e:
            print(f"Error updating notes: {e}")
            if connection:
                connection.rollback()
            return False  
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
                
    def get_status(self, scan_id):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            query = """
                SELECT Status FROM Scans
                WHERE ScanID = %s
            """
            cursor.execute(query, (scan_id,))
            result = cursor.fetchone()
            if result:
                return result[0]  
            else:
                return None  
        except Exception as e:
            print(f"Error Finding status: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
    def set_status(self, scan_id,stat):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()
            cursor = connection.cursor(prepared=True)
            updte_query = """
                UPDATE Scans
                SET Status = %s
                WHERE ScanID = %s
            """
            cursor.execute(updte_query, (stat, scan_id))
            connection.commit()
            return True 
        except Exception as e:
            print(f"Error updating notes: {e}")
            if connection:
                connection.rollback()
            return False  
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
                
