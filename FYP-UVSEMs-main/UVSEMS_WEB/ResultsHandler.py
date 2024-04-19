import base64
import datetime
import io
import os
import textwrap
from click import wrap_text
from flask import app
from reportlab.lib import colors
from EncryptionHandler import decrypt_data, encrypt_data, generate_keynonce
from ScanUtils import ScanUtils
import datetime
from reportlab.platypus import Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer


from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.lib.units import inch

class ResultsHandler:
    def __init__(self, dbConnection):
        self.dbConnection = dbConnection
        self.scanUtil = ScanUtils(dbConnection)
        self.styles = getSampleStyleSheet()
   
    
    def scanID_to_nmapres(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return None

        cursor = None
        try:
            cursor = connection.cursor()
            query = """
            SELECT NmapResID
            FROM NmapResults
            WHERE ScanID = %s;
            """
            cursor.execute(query, (scan_id,))
            results = cursor.fetchall()  # Fetch all rows
            if results:
                nmap_res_ids = [result[0] for result in results]
                print(nmap_res_ids)  # Print the list of NmapResIDs
                return nmap_res_ids
            else:
                print("No nmapResIDs found for that Scan ID")
                return None
        except Exception as e:
            print(f"Database pull error when trying to get nmapResIDs: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
                
                
    def scanID_to_dnsrec(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return None

        cursor = None
        try:
            cursor = connection.cursor()
            query = """
            SELECT DnsRecordID
            FROM DNSRecords
            WHERE ScanID = %s;
            """
            cursor.execute(query, (scan_id,))
            results = cursor.fetchall()  # Fetch all rows
            if results:
                dns_record_ids = [result[0] for result in results]
                print(dns_record_ids)  # Print the list of DNSRecordIDs
                return dns_record_ids
            else:
                print("No DNSRecordIDs found for that Scan ID")
                return None
        except Exception as e:
            print(f"Database error when trying to get DNSRecordIDs: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()       
                
                
                
    def pull_nmap(self, scan_id, nmapresids):
        """
        Gets the NmapResults db entries for a specific scan ID and decrypts them.

        Args:
            scan_id (int): The ID of the scan to retrieve results for.
            nmapresids (list): A list of NmapResIDs to retrieve results for.

        Returns:
            list: A list of dictionaries containing decrypted NmapResults data for the specified scan ID and NmapResIDs.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        cursor = connection.cursor()
        try:
            decrypted_results = []
            for nmapresid in nmapresids:
                query = """
                SELECT NmapResID, ScanID, IPAddress, Hostname, Port, Protocol, ServiceName, ServiceVersion, State, OSFingerPrint, StartTime, EndTime, ScanType, AnalystCVSS
                FROM NmapResults 
                WHERE ScanID = %s AND NmapResID = %s
                """
                cursor.execute(query, (scan_id, nmapresid))
                results = cursor.fetchall()

                for result in results:
                    nmap_res_id, scan_id, ip_address, hostname, port, protocol, service_name, service_version, state, os_fingerprint, start_time, end_time, scan_type, analystCVSS = result

                    # Retrieve encryption key and nonce for the current result
                    key, nonce = self.scanUtil.snatch_nmap_encryption_key(nmapresid)
                    if key is None or nonce is None:
                        print(f"Cannot get the key or nonce for specified ScanID {scan_id}")
                        continue  # Skip ahead

                    # Decrypt the data
                    ip_address = decrypt_data(ip_address, key, nonce) if ip_address else None
                    hostname = decrypt_data(hostname, key, nonce) if hostname else None
                    protocol = decrypt_data(protocol, key, nonce) if protocol else "Not found"
                    service_name = decrypt_data(service_name, key, nonce) if service_name else None
                    service_version = decrypt_data(service_version, key, nonce) if service_version else "Not Found"
                    state = decrypt_data(state, key, nonce) if state else "Not found"
                    os_fingerprint = decrypt_data(os_fingerprint, key, nonce) if os_fingerprint else None

                    decrypted_results.append({
                        'NmapResID': nmap_res_id,
                        'ScanID': scan_id,
                        'IPAddress': ip_address,
                        'Hostname': hostname,
                        'Port': port,
                        'Protocol': protocol,
                        'ServiceName': service_name,
                        'ServiceVersion': service_version,
                        'State': state,
                        'OSFingerPrint': os_fingerprint,
                        'StartTime': start_time,
                        'EndTime': end_time,
                        'ScanType': scan_type,
                        'AnalystCVSS': analystCVSS
                    })

            return decrypted_results
        except Exception as e:
            print(f"Error pulling and decrypting NmapResults data: {str(e)}")
            return []
        finally:
            cursor.close()
            connection.close()
            
    def pull_dns(self, scan_id, dns_record_ids):
        """
        Gets the DNSRecords db entries for a specific scan ID and decrypts them.

        Args:
            scan_id (int): The ID of the scan to retrieve results for.
            dns_record_ids (list): A list of DNSRecordIDs to retrieve results for.

        Returns:
            list: A list of dictionaries containing decrypted DNSRecords data for the specified scan ID and DNSRecordIDs.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        cursor = connection.cursor()
        try:
            decrypted_results = []
            for dns_record_id in dns_record_ids:
                query = """
                SELECT DNSRecordID, RecordType, RecordValue, Date, Domain
                FROM DNSRecords
                WHERE ScanID = %s AND DNSRecordID = %s
                """
                cursor.execute(query, (scan_id, dns_record_id))
                results = cursor.fetchall()

                for result in results:
                    dns_record_id, record_type, encrypted_record_value, date, domain = result

                    # Retrieve encryption key and nonce for the current result
                    key, nonce = self.scanUtil.snatch_dns_encryption_key(dns_record_id)
                    if key is None or nonce is None:
                        print(f"Cannot get the key or nonce for specified DNSRecordID {dns_record_id}")
                        continue  # Skip ahead

                    # Decrypt the RecordValue
                    record_value = decrypt_data(encrypted_record_value, key, nonce) if encrypted_record_value else None

                    decrypted_results.append({
                        'DNSRecordID': dns_record_id,
                        'RecordType': record_type,
                        'RecordValue': record_value,
                        'Date': date,
                        'Domain': domain
                    })

            return decrypted_results
        except Exception as e:
            print(f"Error getting and decrypting DNSRecords data: {str(e)}")
            return []
        finally:
            cursor.close()
            connection.close()
            
            
    def pull_vas_results(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            cursor = connection.cursor(dictionary=True)
            query = """
            SELECT VAS_Res_ID, Port, NVT, Description, Time, Type, HashValue, Severity, AnalystCVSS
            FROM VAS_Results
            WHERE ScanID = %s;
            """
            cursor.execute(query, (scan_id,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            print(f"Database error when pulling VAS_Results: {e}")
            return []
        finally:
          if cursor:
                cursor.close()
          if connection:
                connection.close()

    def pull_zap_results(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            cursor = connection.cursor(dictionary=True)
            query = """
            SELECT ZapResID, Alert, URL, Risk, Detail, Timestamp, Rescan, AnalystCVSS
            FROM Zap_Results
            WHERE ScanID = %s;
            """
            cursor.execute(query, (scan_id,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            print(f"Database error when getting Zap_Results: {e}")
            return []
        finally:
          if cursor:
                cursor.close()
          if connection:
                connection.close()

    def pull_spider_results(self, scan_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            cursor = connection.cursor(dictionary=True)
            query = """
            SELECT SpiderResID,URL, StatusCode, TimeStamp, Method
            FROM Spider
            WHERE ScanID = %s;
            """
            cursor.execute(query, (scan_id,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            print(f"Database problem - error when fetching Spider results: {e}")
            return []
        finally:
          if cursor:
                cursor.close()
          if connection:
                connection.close()
                         
    def is_note_validate(self,user_id):
        connection = None
        cursor = None
        try:
            connection = self.dbConnection.createConnection()  # Assuming dbConnection is your database connection module
            cursor = connection.cursor()
            
            # Get scans without notes for the specified user
            query = """
            SELECT ScanID
            FROM Scans
            WHERE AssignedEngineer = %s
            AND NOT EXISTS (SELECT 1 FROM ScanNotes WHERE Scans.ScanID = ScanNotes.ScanID)
                """
            cursor.execute(query, (user_id,))
            scans_NO_notes = cursor.fetchall()

            # Create notes for scans without notes
            for scan in scans_NO_notes:
                insert_query = "INSERT INTO ScanNotes (ScanID) VALUES (%s)"
                cursor.execute(insert_query, (scan['ScanID'],))
            
            connection.commit()
        except Exception as e:
            print(f"Error checking and creating notes: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
             
    def insert_report(self, scan_id, report_uid, pdf_file_path):
        """
        Inserts a new report record into the Reports table along with the PDF file as a BLOB.

        Args:
            scan_id (int): The ID of the assoc report
            report_uid (str): A unique identifier for the report.
            pdf_file_path (str): The file path to the PDF report to be inserted as a BLOB.
            creation_time (datetime): The creation time of the report.

        Returns:
            int: The generated ReportID of the new report record, or None if insertion fails.
        """

        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to db at function level")
            return None

        cursor = connection.cursor()
        try:
            # Open the PDF file in binary mode and read its contents
            with open(pdf_file_path, 'rb') as pdf_file:
                pdf_data = pdf_file.read()

            # Prepare and execute the insert query to include the PDF BLOB
            query = """
            INSERT INTO Reports (ScanID, ReportUID, ReportPDF, CreationTime)
            VALUES (%s, %s, %s, NOW())
            """
            cursor.execute(query, (scan_id, report_uid, pdf_data))
            connection.commit()

            # Retrieve the last inserted ReportID
            report_id = cursor.lastrowid
            return report_id

        except Exception as e:
            print(f"Error creating new report: {e}")
            connection.rollback()
            return None

        finally:
            cursor.close()
            connection.close()        
             


    def format_datetime(self, dt):
        """Format datetime object to string."""
        if isinstance(dt, datetime.datetime):
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        return dt

    def prepare_data(self, data, header_style, content_style):
        if not data:
            return [["No data available"]]

        if isinstance(data[0], dict):
            headers = list(data[0].keys())
            formatted_headers = [Paragraph('<b>{}</b>'.format(header), header_style) for header in headers]
            formatted_data = [formatted_headers]

            for row in data:
                formatted_row = []
                for header in headers:
                    cell_data = str(row.get(header, ''))
                    wrapped_text = self.wrap_text(cell_data)
                    formatted_row.append(Paragraph(wrapped_text, content_style))
                formatted_data.append(formatted_row)

            return formatted_data
        else:
            return [[Paragraph(self.wrap_text(str(cell)), content_style) for cell in row] for row in data]


    def wrap_text(self, text, max_length=1000):
        """Wrap text if it exceeds max_length."""
        return text if len(text) <= max_length else text[:max_length-3] + '...'

    def calculate_dynamic_widths(self, prepared_data, max_column_width=200, page_width=landscape(letter)[0], left_margin=72, right_margin=72):
        max_widths = [0] * len(prepared_data[0])
        for row in prepared_data:
            for i, cell in enumerate(row):
                cell_width = stringWidth(cell.text, cell.style.fontName, cell.style.fontSize) + 6  
                constrained_width = min(cell_width, max_column_width)
                max_widths[i] = max(max_widths[i], constrained_width)
        
        total_max_allowed_width = page_width - left_margin - right_margin
        if sum(max_widths) > total_max_allowed_width:
            scale_factor = total_max_allowed_width / sum(max_widths)
            max_widths = [width * scale_factor for width in max_widths]
        
        return max_widths



    def generate_and_save_pdf(self, scan_id, nmap_data, dns_data, vas_data, zap_data, spider_data, output_filename):
        doc = SimpleDocTemplate(output_filename, pagesize=landscape(letter), rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        story = []
        
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=self.styles['Heading1'],
            textColor=colors.white,
            fontSize=10,
            backColor=colors.HexColor('#383b69'),
            alignment=1
        )

        table_header_style = self.styles['Normal'].clone('table_header_style', fontSize=6)
        table_content_style = self.styles['Normal'].clone('table_content_style', fontSize=6)

        logo_path = 'static/images/logo.png'
        logo = Image(logo_path, width=1.3*inch, height=1.3*inch)
        story.append(logo)
        story.append(Spacer(1, 10))

        header_text = f'Scan Report for Scan ID: {scan_id}'
        header = Paragraph(header_text, header_style)
        story.append(header)

        sections = [
            ("Nmap Results", nmap_data),
            ("DNS Results", dns_data),
            ("VAS Results", vas_data),
            ("ZAP Results", zap_data),
            ("Spider Results", spider_data),
        ]

        for section_title, section_data in sections:
            section_header = Paragraph(section_title, header_style)
            story.append(section_header)
            
            prepared_data = self.prepare_data(section_data, table_header_style, table_content_style)
            if prepared_data:
                colWidths = self.calculate_dynamic_widths(prepared_data)
                table = Table(prepared_data, colWidths=colWidths, repeatRows=1)
                table.setStyle(TableStyle([
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('GRID', (0,0), (-1,-1), 1, colors.black),
                    ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ]))
                story.append(table)
            else:
                story.append(Paragraph("No data available", self.styles['Normal']))
            story.append(Spacer(1, 10))

        doc.build(story)
        print(f"THe PDF report for Scan ID {scan_id} has been generated and saved: {output_filename}")

    def snatch_reports_user_ana(self, user_id):
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []

        try:
            cursor = connection.cursor(dictionary=True)
            query = """
            SELECT Reports.*, Scans.ScanName, Scans.ScanDate
            FROM Reports
            JOIN Scans ON Reports.ScanID = Scans.ScanID
            WHERE Scans.AssignedAnalyst = %s
            """
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            print(f"Database error when picking up the reports: {e}")
            return []
        finally:
          if cursor:
                cursor.close()
          if connection:
                connection.close()

    def get_dl_report(self, report_id):
        """
        Fetches the report PDF from the database using the provided report ID.

        Args:
            report_id (int): The ID of the report to fetch.

        Returns:
            io.BytesIO: A BytesIO object containing the PDF data if found, otherwise None.
        """
        connection = self.dbConnection.createConnection()
        if connection is None:
            print("Failed to connect to the database")
            return []
        
        try:
            cursor = connection.cursor(prepared=True)  # Use prepared=True for prepared statement
            query = "SELECT ReportPDF FROM Reports WHERE ReportID = %s"
            cursor.execute(query, (report_id,))  # Parameters are passed as a tuple
            report_blob = cursor.fetchone()
                
            if report_blob:
                    # Convert the BLOB to a BytesIO object and return it
                pdf_bytes = io.BytesIO(report_blob[0])
                return pdf_bytes
            else:
                return None
        finally:
                cursor.close()
                connection.close()
                
                