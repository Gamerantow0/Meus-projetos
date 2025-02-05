import logging
from hashlib import sha256, pbkdf2_hmac
import re
from typing import Optional, Dict, List
import os
from datetime import datetime
import json
import argparse
import sys
import time
from cryptography.fernet import Fernet
import base64

class SecurityMonitor:
    def __init__(self):
        self._setup_logging()
        self.failed_attempts = {}
        self.MAX_ATTEMPTS = 3
        self.LOCKOUT_TIME = 300  # 5 minutes in seconds
        self.MASTER_KEY = self._generate_master_key()

    def _setup_logging(self):
        """Configure secure logging with enhanced format"""
        logging_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=logging_format,
            handlers=[
                logging.FileHandler('security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('security_monitor')

    def _generate_master_key(self) -> bytes:
        """Generate a secure master key and save it to a file if it doesn't already exist"""
        try:
            if os.path.exists('key_decrypt'):
                with open('key_decrypt', 'rb') as key_file:
                    key = key_file.read()
                self.logger.info("Loaded existing master key")
            else:
                key = base64.urlsafe_b64encode(os.urandom(32))
                self.logger.info("Generated new master key")
                with open('key_decrypt', 'wb') as key_file:
                    key_file.write(key)
            return key if isinstance(key, bytes) else key.encode()
        except Exception as e:
            self.logger.error(f"Error generating or loading master key: {str(e)}")
            raise

    def check_password_strength(self, password: str) -> Dict[str, bool]:
        """Enhanced password validation with multiple security checks"""
        if not password:
            return {check: False for check in ['length', 'uppercase', 'lowercase', 
                                             'numbers', 'special', 'no_common', 
                                             'no_sequential', 'no_repeated']}

        checks = {
            'length': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_common': password.lower() not in ['password123', 'admin123', '12345678'],
            'no_sequential': not re.search(r'(abc|123|qwe|xyz)', password.lower()),
            'no_repeated': not re.search(r'(.)\1{2,}', password)
        }
        return checks

    def scan_file(self, filename: str) -> Dict[str, List[str]]:
        """Scan file for potential security issues"""
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File {filename} not found")

        issues = {
            'passwords': [],
            'api_keys': [],
            'sensitive_data': []
        }

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                
            patterns = {
                'passwords': r'(?i)(password|pwd|pass).*?[=:]\s*[\'"](.+?)[\'"]',
                'api_keys': r'(?i)(api[_-]?key|secret|token).*?[=:]\s*[\'"](.+?)[\'"]',
                'sensitive_data': [
                    r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN
                    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'  # Credit Card
                ]
            }

            for key, pattern in patterns.items():
                if isinstance(pattern, str):
                    matches = re.finditer(pattern, content)
                    issues[key].extend(match.group() for match in matches)
                else:
                    for p in pattern:
                        issues[key].extend(re.findall(p, content))
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Error scanning file {filename}: {str(e)}")
            raise

    def encrypt_file(self, filename: str) -> bool:
        """Encrypt a file using Fernet symmetric encryption"""
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File {filename} not found")

            fernet = Fernet(self.MASTER_KEY)
            
            with open(filename, 'rb') as f:
                data = f.read()
            
            encrypted_data = fernet.encrypt(data)
            encrypted_filename = os.path.splitext(filename)[0] + '.enc'
            
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)
            
            os.remove(filename)  # Remove o arquivo original
            
            self.logger.info(f"File encrypted successfully: {encrypted_filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error encrypting file {filename}: {str(e)}")
            return False

    def decrypt_file(self, encrypted_filename: str, key: Optional[str] = None) -> bool:
        """Decrypt a previously encrypted file using the provided key or the master key from key_decrypt file"""
        try:
            if not os.path.exists(encrypted_filename):
                raise FileNotFoundError(f"File {encrypted_filename} not found")

            if not encrypted_filename.endswith('.enc'):
                raise ValueError("File must have .enc extension")

            if key:
                fernet_key = key.encode()
            else:
                with open('key_decrypt', 'rb') as key_file:
                    fernet_key = key_file.read()

            fernet = Fernet(fernet_key)
            
            with open(encrypted_filename, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            output_filename = os.path.splitext(encrypted_filename)[0] + '.txt'
            
            with open(output_filename, 'wb') as f:
                f.write(decrypted_data)
            
            os.remove(encrypted_filename)  # Remove o arquivo criptografado
            if not key:
                os.remove('key_decrypt')  # Remove a chave mestre
            
            self.logger.info(f"File decrypted successfully: {output_filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error decrypting file {encrypted_filename}: {str(e)}")
            return False

def show_help():
    """Display help information about the Security Monitor tool"""
    help_text = """
Security Monitor Tool Help
=========================

Available Functions:
------------------
1. Scan File (--action scan --target <file_path>)
2. Check Password Strength (--action check-password --target <password>)
3. Encrypt File (--action encrypt --target <file_path>)
4. Decrypt File (--action decrypt --target <file_path> --key <key>)
5. Rename Encrypted File (--action rename --target <old_file> --new-name <new_file>)

For more details, use: python security_monitor.py --help-details
"""
    print(help_text)

def main():
    parser = argparse.ArgumentParser(description='Security Monitor CLI Tool')
    parser.add_argument('--action', 
                       choices=['scan', 'check-password', 'encrypt', 'decrypt', 'rename'],
                       help='Action to perform')
    parser.add_argument('--target', help='File path or password string to analyze')
    parser.add_argument('--new-name', help='New filename for rename operation')
    parser.add_argument('--key', help='Key for decryption')
    parser.add_argument('--help-details', action='store_true', help='Show detailed help')
    
    args = parser.parse_args()

    if args.help_details or not args.action:
        show_help()
        return

    try:
        monitor = SecurityMonitor()

        if not args.target:
            raise ValueError("--target argument is required")

        if args.action == 'scan':
            result = monitor.scan_file(args.target)
            print("\nScan Results:")
            print(json.dumps(result, indent=2))
            
        elif args.action == 'check-password':
            result = monitor.check_password_strength(args.target)
            print("\nPassword Strength Analysis:")
            for check, passed in result.items():
                status = "✅" if passed else "❌"
                print(f"{status} {check.replace('_', ' ').title()}")
            print(f"\nOverall: {'🟢 Strong' if all(result.values()) else '🔴 Weak'} password")
            
        elif args.action == 'encrypt':
            success = monitor.encrypt_file(args.target)
            print("✅ File encrypted successfully" if success else "❌ Encryption failed")
                
        elif args.action == 'decrypt':
            success = monitor.decrypt_file(args.target, args.key)
            print("✅ File decrypted successfully" if success else "❌ Decryption failed")
        
        elif args.action == 'rename':
            if not args.new_name:
                raise ValueError("--new-name argument is required for rename operation")
            success = monitor.rename_encrypted_file(args.target, args.new_name)
            print("✅ File renamed successfully" if success else "❌ Rename failed")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()