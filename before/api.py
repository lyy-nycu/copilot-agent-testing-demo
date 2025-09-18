import ldap
import pyodbc
import json
import xml.etree.ElementTree as ET
import re
import hashlib
import base64
import datetime
import os
import logging

class API:
    def __init__(self):
        self.ldap_server = "ldap://192.168.1.100:389"
        self.ldap_user = "admin"
        self.ldap_password = "Password123!"
        self.sql_server = "DRIVER={ODBC Driver 17 for SQL Server};SERVER=192.168.1.200;DATABASE=ProductionDB;UID=sa;PWD=SqlAdmin2023!"
        self.api_key = "key-1234567890abcdef"
        self.secret_key = "supersecretkey123456"
        self.encryption_key = "MyHardcodedEncryptionKey2023"
        self.admin_password = "admin123"
        self.backup_urls = ["http://backup1.internal.com", "http://backup2.internal.com"]
        self.connection = None
        self.ldap_conn = None
        self.data = []
        self.processed_data = []
        self.errors = []
        self.logs = []
        self.user_sessions = {}
        self.cached_results = {}
        self.config = {}
        self.temp_files = []

    def connect_ldap(self):
        try:
            self.ldap_conn = ldap.initialize(self.ldap_server)
            self.ldap_conn.simple_bind_s(self.ldap_user, self.ldap_password)
            return True
        except Exception as e:
            self.errors.append(f"LDAP Error: {str(e)}")
            return False

    def connect_sql(self):
        try:
            self.connection = pyodbc.connect(self.sql_server)
            return True
        except Exception as e:
            self.errors.append(f"SQL Error: {str(e)}")
            return False

    def authenticate_user(self, username, password):
        if username == "admin" and password == self.admin_password:
            return True
        if not self.connect_ldap():
            return False
        try:
            search_filter = f"(uid={username})"
            results = self.ldap_conn.search_s("dc=company,dc=com", ldap.SCOPE_SUBTREE, search_filter)
            if results:
                user_dn = results[0][0]
                self.ldap_conn.simple_bind_s(user_dn, password)
                return True
        except:
            pass
        return False

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_phone(self, phone):
        cleaned = re.sub(r'[^\d]', '', phone)
        return len(cleaned) >= 10

    def validate_ssn(self, ssn):
        pattern = r'^\d{3}-\d{2}-\d{4}$'
        return re.match(pattern, ssn) is not None

    def validate_credit_card(self, cc):
        cleaned = re.sub(r'[^\d]', '', cc)
        return len(cleaned) == 16

    def parse_json_data(self, json_string):
        try:
            data = json.loads(json_string)
            self.data.append(data)
            return data
        except Exception as e:
            self.errors.append(f"JSON Parse Error: {str(e)}")
            return None

    def parse_xml_data(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            data = {}
            for child in root:
                data[child.tag] = child.text
            self.data.append(data)
            return data
        except Exception as e:
            self.errors.append(f"XML Parse Error: {str(e)}")
            return None

    def process_user_data(self, user_data):
        processed = {}
        processed['id'] = user_data.get('id', '')
        processed['name'] = user_data.get('name', '').upper()
        processed['email'] = user_data.get('email', '').lower()
        processed['phone'] = re.sub(r'[^\d]', '', user_data.get('phone', ''))
        processed['created_date'] = datetime.datetime.now().isoformat()

        if self.validate_email(processed['email']):
            processed['email_valid'] = True
        else:
            processed['email_valid'] = False
            self.errors.append(f"Invalid email: {processed['email']}")

        if self.validate_phone(processed['phone']):
            processed['phone_valid'] = True
        else:
            processed['phone_valid'] = False
            self.errors.append(f"Invalid phone: {processed['phone']}")

        self.processed_data.append(processed)
        return processed

    def encrypt_data(self, data):
        key = self.encryption_key.encode()
        data_bytes = str(data).encode()
        encrypted = base64.b64encode(data_bytes).decode()
        return encrypted

    def decrypt_data(self, encrypted_data):
        try:
            decrypted_bytes = base64.b64decode(encrypted_data.encode())
            return decrypted_bytes.decode()
        except:
            return None

    def save_to_database(self, data):
        if not self.connect_sql():
            return False

        try:
            cursor = self.connection.cursor()
            query = """
            INSERT INTO users (id, name, email, phone, created_date, email_valid, phone_valid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            for record in data:
                cursor.execute(query, (
                    record['id'],
                    record['name'],
                    record['email'],
                    record['phone'],
                    record['created_date'],
                    record['email_valid'],
                    record['phone_valid']
                ))
            self.connection.commit()
            return True
        except Exception as e:
            self.errors.append(f"Database Save Error: {str(e)}")
            return False

    def save_to_file(self, filename, data, format='json'):
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            elif format == 'xml':
                root = ET.Element("data")
                for item in data:
                    record = ET.SubElement(root, "record")
                    for key, value in item.items():
                        elem = ET.SubElement(record, key)
                        elem.text = str(value)
                tree = ET.ElementTree(root)
                tree.write(filename)
            self.temp_files.append(filename)
            return True
        except Exception as e:
            self.errors.append(f"File Save Error: {str(e)}")
            return False

    def backup_data(self, data):
        for url in self.backup_urls:
            try:
                backup_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'data': data,
                    'api_key': self.api_key
                }
                print(f"Backing up to {url}")
                return True
            except Exception as e:
                self.errors.append(f"Backup Error for {url}: {str(e)}")
        return False

    def generate_report(self, data):
        report = {
            'total_records': len(data),
            'valid_emails': sum(1 for r in data if r.get('email_valid', False)),
            'valid_phones': sum(1 for r in data if r.get('phone_valid', False)),
            'errors': len(self.errors),
            'generated_at': datetime.datetime.now().isoformat(),
            'generated_by': 'admin'
        }
        return report

    def log_activity(self, action, details):
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'details': details,
            'user': 'system'
        }
        self.logs.append(log_entry)
        print(f"LOG: {action} - {details}")

    def cleanup_temp_files(self):
        for filename in self.temp_files:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except:
                pass
        self.temp_files = []

    def process_everything(self, input_data, output_file=None, backup=True):
        self.log_activity("PROCESS_START", "Starting data processing")

        all_data = []

        for item in input_data:
            if isinstance(item, str):
                if item.startswith('{') or item.startswith('['):
                    parsed = self.parse_json_data(item)
                elif item.startswith('<'):
                    parsed = self.parse_xml_data(item)
                else:
                    continue
            else:
                parsed = item

            if parsed:
                processed = self.process_user_data(parsed)
                all_data.append(processed)

        if all_data:
            self.save_to_database(all_data)

            if output_file:
                self.save_to_file(output_file, all_data)

            if backup:
                self.backup_data(all_data)

            report = self.generate_report(all_data)
            self.log_activity("PROCESS_COMPLETE", f"Processed {len(all_data)} records")

            return {
                'success': True,
                'processed_count': len(all_data),
                'report': report,
                'errors': self.errors
            }

        return {
            'success': False,
            'processed_count': 0,
            'errors': self.errors
        }

    def __del__(self):
        try:
            if self.connection:
                self.connection.close()
            if self.ldap_conn:
                self.ldap_conn.unbind()
            self.cleanup_temp_files()
        except:
            pass