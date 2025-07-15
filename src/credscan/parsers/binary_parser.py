"""
Binary file parser for handling archives, databases, and other binary formats.
Supports secure extraction and credential detection in binary files.
"""

import os
import tempfile
import shutil
import sqlite3
import zipfile
import tarfile
import logging
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import hashlib
import time

try:
    import py7zr
    HAS_7ZIP = True
except ImportError:
    HAS_7ZIP = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

logger = logging.getLogger(__name__)


class BinaryFileParser:
    """Parser for binary files including archives, databases, and certificate files."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the binary file parser."""
        self.config = config or {}
        
        # Security limits
        self.max_extraction_size = self.config.get('max_extraction_size', 100 * 1024 * 1024)  # 100MB
        self.max_extraction_depth = self.config.get('max_extraction_depth', 5)
        self.max_files_per_archive = self.config.get('max_files_per_archive', 1000)
        self.extraction_timeout = self.config.get('extraction_timeout', 300)  # 5 minutes
        
        # Supported file types
        self.archive_extensions = {'.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.7z'}
        self.database_extensions = {'.sqlite', '.sqlite3', '.db', '.db3'}
        self.certificate_extensions = {'.p12', '.pfx', '.jks', '.keystore'}
        self.application_extensions = {'.jar', '.war', '.ear', '.apk', '.ipa'}
        
        # Combine all supported extensions
        self.supported_extensions = (
            self.archive_extensions | 
            self.database_extensions | 
            self.certificate_extensions | 
            self.application_extensions
        )
        
        # Temporary directory management
        self.temp_dirs = []
        
    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file."""
        file_path_lower = file_path.lower()
        
        # Check simple extensions first
        for ext in self.supported_extensions:
            if file_path_lower.endswith(ext):
                return True
        
        # Check compound extensions
        compound_extensions = ['.tar.gz', '.tar.bz2']
        for ext in compound_extensions:
            if file_path_lower.endswith(ext):
                return True
        
        return False
    
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse a binary file and extract credential information."""
        try:
            start_time = time.time()
            
            # Check file size before processing
            file_size = os.path.getsize(file_path)
            if file_size > self.max_extraction_size:
                logger.warning(f"File {file_path} exceeds size limit ({file_size} bytes)")
                return self._create_error_result(f"File too large: {file_size} bytes")
            
            # Determine file type and parse accordingly
            file_ext = self._get_file_extension(file_path)
            
            if file_ext in self.archive_extensions or file_ext in self.application_extensions:
                result = self._parse_archive(file_path)
            elif file_ext in self.database_extensions:
                result = self._parse_database(file_path)
            elif file_ext in self.certificate_extensions:
                result = self._parse_certificate(file_path)
            else:
                return self._create_error_result(f"Unsupported file type: {file_ext}")
            
            # Add processing time
            processing_time = time.time() - start_time
            result['processing_time'] = round(processing_time, 2)
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing binary file {file_path}: {e}")
            return self._create_error_result(str(e))
        finally:
            self._cleanup_temp_dirs()
    
    def _get_file_extension(self, file_path: str) -> str:
        """Get the file extension, handling compound extensions."""
        file_path_lower = file_path.lower()
        
        # Check for compound extensions first
        compound_extensions = ['.tar.gz', '.tar.bz2']
        for ext in compound_extensions:
            if file_path_lower.endswith(ext):
                return ext
        
        # Return simple extension
        return Path(file_path).suffix.lower()
    
    def _create_temp_dir(self) -> str:
        """Create a secure temporary directory."""
        temp_dir = tempfile.mkdtemp(prefix='credscan_binary_')
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    def _cleanup_temp_dirs(self):
        """Clean up all temporary directories."""
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to clean up temp directory {temp_dir}: {e}")
        self.temp_dirs.clear()
    
    def _is_safe_path(self, path: str, extraction_path: str) -> bool:
        """Check if extraction path is safe (prevents path traversal attacks)."""
        abs_extraction_path = os.path.abspath(extraction_path)
        abs_target_path = os.path.abspath(os.path.join(extraction_path, path))
        return abs_target_path.startswith(abs_extraction_path)
    
    def _parse_archive(self, file_path: str) -> Dict[str, Any]:
        """Parse archive files (ZIP, TAR, 7Z, JAR, WAR, APK, IPA)."""
        items = []
        temp_dir = self._create_temp_dir()
        files_extracted = 0
        
        try:
            file_ext = self._get_file_extension(file_path)
            
            # Extract archive based on type
            if file_ext == '.zip' or file_ext in self.application_extensions:
                files_extracted = self._extract_zip(file_path, temp_dir)
            elif file_ext.startswith('.tar'):
                files_extracted = self._extract_tar(file_path, temp_dir)
            elif file_ext == '.7z' and HAS_7ZIP:
                files_extracted = self._extract_7z(file_path, temp_dir)
            else:
                return self._create_error_result(f"Unsupported archive format: {file_ext}")
            
            # Parse extracted files
            items = self._parse_extracted_files(temp_dir)
            
            return {
                'type': 'binary_archive',
                'items': items,
                'archive_type': file_ext,
                'files_extracted': files_extracted,
                'extraction_path': temp_dir
            }
            
        except Exception as e:
            logger.error(f"Error parsing archive {file_path}: {e}")
            return self._create_error_result(str(e))
    
    def _extract_zip(self, file_path: str, temp_dir: str) -> int:
        """Safely extract ZIP files."""
        files_extracted = 0
        
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            for member in zip_file.infolist():
                if files_extracted >= self.max_files_per_archive:
                    logger.warning(f"Reached max files limit for {file_path}")
                    break
                
                # Check for path traversal
                if not self._is_safe_path(member.filename, temp_dir):
                    logger.warning(f"Unsafe path in ZIP: {member.filename}")
                    continue
                
                # Check file size
                if member.file_size > self.max_extraction_size:
                    logger.warning(f"File too large in ZIP: {member.filename}")
                    continue
                
                try:
                    zip_file.extract(member, temp_dir)
                    files_extracted += 1
                except Exception as e:
                    logger.warning(f"Failed to extract {member.filename}: {e}")
                    continue
        
        return files_extracted
    
    def _extract_tar(self, file_path: str, temp_dir: str) -> int:
        """Safely extract TAR files."""
        files_extracted = 0
        
        # Determine compression mode
        if file_path.lower().endswith(('.tar.gz', '.tgz')):
            mode = 'r:gz'
        elif file_path.lower().endswith(('.tar.bz2', '.tbz2')):
            mode = 'r:bz2'
        else:
            mode = 'r'
        
        with tarfile.open(file_path, mode) as tar_file:
            for member in tar_file.getmembers():
                if files_extracted >= self.max_files_per_archive:
                    logger.warning(f"Reached max files limit for {file_path}")
                    break
                
                # Check for path traversal
                if not self._is_safe_path(member.name, temp_dir):
                    logger.warning(f"Unsafe path in TAR: {member.name}")
                    continue
                
                # Check file size
                if member.size > self.max_extraction_size:
                    logger.warning(f"File too large in TAR: {member.name}")
                    continue
                
                try:
                    tar_file.extract(member, temp_dir)
                    files_extracted += 1
                except Exception as e:
                    logger.warning(f"Failed to extract {member.name}: {e}")
                    continue
        
        return files_extracted
    
    def _extract_7z(self, file_path: str, temp_dir: str) -> int:
        """Safely extract 7Z files."""
        if not HAS_7ZIP:
            raise ImportError("py7zr library required for 7Z support")
        
        files_extracted = 0
        
        with py7zr.SevenZipFile(file_path, mode='r') as archive:
            for info in archive.list():
                if files_extracted >= self.max_files_per_archive:
                    logger.warning(f"Reached max files limit for {file_path}")
                    break
                
                # Check for path traversal
                if not self._is_safe_path(info.filename, temp_dir):
                    logger.warning(f"Unsafe path in 7Z: {info.filename}")
                    continue
                
                try:
                    archive.extract(temp_dir, [info.filename])
                    files_extracted += 1
                except Exception as e:
                    logger.warning(f"Failed to extract {info.filename}: {e}")
                    continue
        
        return files_extracted
    
    def _parse_extracted_files(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Parse extracted files for credentials."""
        items = []
        
        # Import other parsers to handle extracted files
        try:
            from .code_parser import CodeParser
            from .json_parser import JSONParser
            from .yaml_parser import YAMLParser
            
            parsers = [
                CodeParser(self.config),
                JSONParser(self.config),
                YAMLParser(self.config)
            ]
        except ImportError as e:
            logger.warning(f"Could not import parsers: {e}")
            return items
        
        # Walk through extracted files
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, temp_dir)
                
                logger.debug(f"Processing extracted file: {relative_path}")
                
                # Try each parser on the extracted file
                for parser in parsers:
                    if parser.can_parse(file_path):
                        try:
                            logger.debug(f"Using {parser.__class__.__name__} for {relative_path}")
                            parsed_result = parser.parse(file_path)
                            
                            if parsed_result and parsed_result.get('items'):
                                logger.debug(f"Found {len(parsed_result['items'])} items in {relative_path}")
                                
                                # Add archive context to items and ensure proper formatting
                                for item in parsed_result['items']:
                                    item['archive_path'] = relative_path
                                    # Ensure the item has the required fields for rule matching
                                    if 'line' not in item:
                                        item['line'] = item.get('line_number', 1)
                                    
                                    # Debug the item format
                                    logger.debug(f"Extracted item: key='{item.get('key')}' value='{str(item.get('value', ''))[:30]}...'")
                                
                                items.extend(parsed_result['items'])
                                break  # Use first successful parser
                        except Exception as e:
                            logger.warning(f"Parser {parser.__class__.__name__} failed for {file_path}: {e}")
                            continue
                
                # If no parser handled the file, log it
                if not any(p.can_parse(file_path) for p in parsers):
                    logger.debug(f"No parser available for extracted file: {relative_path}")
        
        return items
    
    def _parse_database(self, file_path: str) -> Dict[str, Any]:
        """Parse SQLite database files."""
        items = []
        
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            # Common table names that might contain credentials
            credential_tables = {
                'users', 'user', 'accounts', 'account', 'auth', 'authentication',
                'credentials', 'config', 'configuration', 'settings', 'properties',
                'tokens', 'sessions', 'keys', 'secrets'
            }
            
            for (table_name,) in tables:
                table_lower = table_name.lower()
                
                # Check if table name suggests it might contain credentials
                might_have_creds = any(keyword in table_lower for keyword in credential_tables)
                
                if might_have_creds:
                    try:
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns = cursor.fetchall()
                        
                        # Look for credential-like column names
                        cred_columns = []
                        for col_info in columns:
                            col_name = col_info[1].lower()
                            if any(keyword in col_name for keyword in 
                                  ['password', 'token', 'key', 'secret', 'auth', 'api']):
                                cred_columns.append(col_info[1])
                        
                        if cred_columns:
                            # Query the table for potential credentials
                            query = f"SELECT {', '.join(cred_columns)} FROM {table_name} LIMIT 100"
                            cursor.execute(query)
                            rows = cursor.fetchall()
                            
                            for i, row in enumerate(rows):
                                for j, value in enumerate(row):
                                    if value and isinstance(value, str) and len(value) > 8:
                                        items.append({
                                            'type': 'database_value',
                                            'key': cred_columns[j],
                                            'value': value,
                                            'table': table_name,
                                            'row': i + 1,
                                            'line': i + 1  # For compatibility
                                        })
                    
                    except sqlite3.Error as e:
                        logger.debug(f"Error querying table {table_name}: {e}")
                        continue
            
            conn.close()
            
            return {
                'type': 'binary_database',
                'items': items,
                'database_type': 'sqlite',
                'tables_found': len(tables)
            }
            
        except sqlite3.Error as e:
            return self._create_error_result(f"SQLite error: {e}")
    
    def _parse_certificate(self, file_path: str) -> Dict[str, Any]:
        """Parse certificate files (P12, PFX, JKS)."""
        if not HAS_CRYPTOGRAPHY:
            return self._create_error_result("cryptography library required for certificate parsing")
        
        items = []
        file_ext = self._get_file_extension(file_path)
        
        try:
            if file_ext in {'.p12', '.pfx'}:
                items = self._parse_pkcs12(file_path)
            elif file_ext in {'.jks', '.keystore'}:
                items = self._parse_jks(file_path)
            
            return {
                'type': 'binary_certificate',
                'items': items,
                'certificate_type': file_ext
            }
            
        except Exception as e:
            return self._create_error_result(f"Certificate parsing error: {e}")
    
    def _parse_pkcs12(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse PKCS#12 certificate files."""
        items = []
        
        try:
            with open(file_path, 'rb') as f:
                p12_data = f.read()
            
            # Try common passwords first
            common_passwords = [b'', b'password', b'changeit', b'123456', b'default']
            
            for password in common_passwords:
                try:
                    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                        p12_data, password
                    )
                    
                    # Extract certificate information
                    if certificate:
                        subject = certificate.subject.rfc4514_string()
                        issuer = certificate.issuer.rfc4514_string()
                        
                        items.append({
                            'type': 'certificate_info',
                            'key': 'certificate_subject',
                            'value': subject,
                            'line': 1,
                            'additional_info': {
                                'issuer': issuer,
                                'password_used': password.decode('utf-8', errors='ignore'),
                                'has_private_key': private_key is not None
                            }
                        })
                    
                    break  # Successfully parsed with this password
                    
                except Exception:
                    continue  # Try next password
            
        except Exception as e:
            logger.debug(f"PKCS#12 parsing failed: {e}")
        
        return items
    
    def _parse_jks(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Java KeyStore files."""
        items = []
        
        try:
            # Try to use pyjks if available
            import pyjks
            
            common_passwords = ['', 'password', 'changeit', '123456', 'default']
            
            for password in common_passwords:
                try:
                    keystore = pyjks.KeyStore.load(file_path, password)
                    
                    # Extract keystore information
                    items.append({
                        'type': 'keystore_info',
                        'key': 'keystore_type',
                        'value': 'JKS',
                        'line': 1,
                        'additional_info': {
                            'password_used': password,
                            'entries_count': len(keystore.entries)
                        }
                    })
                    
                    break  # Successfully parsed with this password
                    
                except Exception:
                    continue  # Try next password
            
        except ImportError:
            logger.warning("pyjks library not available for JKS parsing")
        except Exception as e:
            logger.debug(f"JKS parsing failed: {e}")
        
        return items
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """Create an error result."""
        return {
            'type': 'binary_error',
            'items': [],
            'error': error_message
        }
    
    def __del__(self):
        """Cleanup temporary directories on deletion."""
        self._cleanup_temp_dirs()