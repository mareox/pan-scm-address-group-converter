#!/usr/bin/env python3
"""
Strata Cloud Manager Address Group Conversion Tool

This script automates the conversion of static address groups to dynamic address groups
by tagging all address objects within a static group and then converting the group to
a dynamic type based on that new tag.

Features:
- OAuth 2.0 Client Credentials authentication
- Single folder operation for better control
- Batch processing with progress reporting
- Comprehensive error handling and retry logic
- Configuration backup and rollback capability
- Structured logging and detailed reporting
- Command-line interface with dry-run mode

Requirements:
- Environment variables: SCM_CLIENT_ID, SCM_CLIENT_SECRET, SCM_TSG_ID
- pan-scm-sdk: https://github.com/cdot65/pan-scm-sdk
"""

import argparse
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

# Global SSL bypass flag - will be set by command line args before SDK import
_SSL_BYPASS_ENABLED = False

def enable_ssl_bypass():
    """Enable SSL bypass at module level before SDK import."""
    global _SSL_BYPASS_ENABLED
    if _SSL_BYPASS_ENABLED:
        return  # Already enabled
    
    try:
        # Set environment variables
        os.environ['PYTHONHTTPSVERIFY'] = '0'
        os.environ['CURL_CA_BUNDLE'] = ''
        os.environ['REQUESTS_CA_BUNDLE'] = ''
        
        # Configure global SSL context
        ssl._create_default_https_context = ssl._create_unverified_context
        
        # Disable urllib3 warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Patch requests
        import requests
        requests.packages.urllib3.disable_warnings()
        
        # Override all session requests to use verify=False
        original_request = requests.Session.request
        def patched_request(self, method, url, **kwargs):
            kwargs['verify'] = False  # Force verify=False
            return original_request(self, method, url, **kwargs)
        requests.Session.request = patched_request
        
        _SSL_BYPASS_ENABLED = True
        print(f"{Colors.RED}⚠️  SSL certificate verification DISABLED globally{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}Failed to configure SSL bypass: {e}{Colors.RESET}")

# Colors class needs to be defined early
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_CYAN = '\033[96m'

try:
    import requests
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Error importing required packages: {e}")
    print("Please install dependencies: uv pip install -r requirements.txt")
    sys.exit(1)

# Import SDK components
try:
    from scm.client import Scm
    from scm.config.objects import Address, AddressGroup, Tag
    from scm.config.setup import Folder
    from scm.exceptions import (
        APIError,
        AuthenticationError,
        InvalidObjectError,
        MissingQueryParameterError,
        NameNotUniqueError,
        NotFoundError,
        ObjectNotPresentError,
        ReferenceNotZeroError,
    )
    # Note: CandidatePush and Jobs are methods on the client, not separate classes
except ImportError as e:
    print(f"Error importing pan-scm-sdk: {e}")
    print("Please install the SDK: uv pip install pan-scm-sdk")
    print("Or run: uv pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ANSI color codes for enhanced console output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_CYAN = '\033[96m'


class ConversionError(Exception):
    """Custom exception for conversion-related errors."""
    pass


class SCMAddressGroupConverter:
    """
    Main class for converting static address groups to dynamic ones.
    
    This class handles the entire workflow from authentication to conversion,
    including backup, tagging, and reporting capabilities.
    """
    
    def __init__(self, dry_run: bool = False, verbose: bool = False, batch_size: int = 50, skip_ssl_verify: bool = False):
        """
        Initialize the converter with configuration options.
        
        Args:
            dry_run: If True, simulate all operations without making changes
            verbose: If True, enable debug-level logging
            batch_size: Number of objects to process in each batch
            skip_ssl_verify: If True, skip SSL certificate verification (DEVELOPMENT ONLY)
        """
        self.dry_run = dry_run
        self.batch_size = batch_size
        self.skip_ssl_verify = skip_ssl_verify
        self.client: Optional[Scm] = None
        self.folder_name: Optional[str] = None
        
        # Initialize managers (will be set after authentication)
        self.address_manager: Optional[Address] = None
        self.address_group_manager: Optional[AddressGroup] = None
        self.tag_manager: Optional[Tag] = None
        self.folder_manager: Optional[Folder] = None
        
        # Tracking variables
        self.backup_data: Dict = {}
        self.created_tags: List[str] = []
        self.processed_objects: List[str] = []
        self.non_interactive: bool = False  # Set via command-line --all flag
        self.conversion_stats: Dict = {
            'objects_tagged': 0,
            'groups_converted': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Configure logging level
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug logging enabled")
        
        # Setup logging file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f"logs/address_group_conversion_{timestamp}.log"
        
        # Add file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Configure SSL settings if bypass requested
        if self.skip_ssl_verify:
            try:
                # Import required modules first
                import requests
                import urllib3
                
                # Disable SSL warnings
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                # Set global SSL context to disable verification
                import ssl
                ssl._create_default_https_context = ssl._create_unverified_context
                
                # Set environment variables for SSL bypass
                os.environ['PYTHONHTTPSVERIFY'] = '0'
                os.environ['CURL_CA_BUNDLE'] = ''
                os.environ['REQUESTS_CA_BUNDLE'] = ''
                
                # Configure requests and urllib3 SSL bypass
                
                # Disable SSL warnings
                try:
                    requests.packages.urllib3.disable_warnings()
                    urllib3.disable_warnings()
                except:
                    pass
                
                # Override urllib3 SSL context creation if available
                try:
                    from urllib3.util.ssl_ import create_urllib3_context
                    
                    def create_unverified_urllib3_context(*args, **kwargs):
                        context = create_urllib3_context(*args, **kwargs)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        return context
                    
                    urllib3.util.ssl_.create_urllib3_context = create_unverified_urllib3_context
                except ImportError:
                    pass
                
                # Patch the default session verify setting
                try:
                    original_request = requests.Session.request
                    def patched_request(self, method, url, **kwargs):
                        kwargs.setdefault('verify', False)
                        return original_request(self, method, url, **kwargs)
                    requests.Session.request = patched_request
                except:
                    pass
                
                logger.warning("⚠️  SSL certificate verification DISABLED - for development/testing only!")
                logger.warning("⚠️  This should NEVER be used in production environments!")
                
            except Exception as e:
                logger.error(f"Failed to configure SSL bypass: {e}")
                logger.warning("SSL bypass may not be fully effective")
        
        logger.info(f"SCM Address Group Converter initialized (dry_run={dry_run}, batch_size={batch_size}, ssl_verify={not skip_ssl_verify})")
        logger.info(f"Log file: {self.log_file}")

    def _print_colored(self, message: str, color: str = Colors.RESET, bold: bool = False):
        """Print colored message to console."""
        prefix = Colors.BOLD if bold else ""
        print(f"{prefix}{color}{message}{Colors.RESET}")

    def _log_section(self, title: str):
        """Log a section header with visual separation."""
        separator = "=" * 70
        logger.info("")
        logger.info(separator)
        logger.info(f"  {title.upper()}")
        logger.info(separator)
        
        # Also print to console with colors
        self._print_colored(f"\n{separator}", Colors.BRIGHT_CYAN, bold=True)
        self._print_colored(f"  {title.upper()}", Colors.BRIGHT_CYAN, bold=True)
        self._print_colored(f"{separator}", Colors.BRIGHT_CYAN, bold=True)

    def _log_success(self, message: str):
        """Log success message with color."""
        logger.info(f"✓ {message}")
        self._print_colored(f"✓ {message}", Colors.BRIGHT_GREEN)

    def _log_warning(self, message: str):
        """Log warning message with color."""
        logger.warning(f"⚠ {message}")
        self._print_colored(f"⚠ {message}", Colors.BRIGHT_YELLOW)

    def _log_error(self, message: str, error: Optional[Exception] = None):
        """Log error message with color."""
        error_msg = f"✘ {message}"
        if error:
            error_msg += f" - {error}"
        logger.error(error_msg)
        self._print_colored(error_msg, Colors.RED)

    def load_credentials(self) -> Tuple[str, str, str]:
        """
        Load credentials from environment variables or .env file.
        
        Returns:
            Tuple of (client_id, client_secret, tsg_id)
            
        Raises:
            ConversionError: If required credentials are missing
        """
        self._log_section("LOADING CREDENTIALS")
        
        # Try to load from .env file
        env_paths = [Path(".env"), Path(__file__).parent / ".env"]
        
        for env_path in env_paths:
            if env_path.exists():
                load_dotenv(dotenv_path=env_path)
                logger.info(f"Loaded environment variables from {env_path}")
                break
        else:
            logger.info("No .env file found, using system environment variables")

        # Get credentials
        client_id = os.environ.get("SCM_CLIENT_ID")
        client_secret = os.environ.get("SCM_CLIENT_SECRET")
        tsg_id = os.environ.get("SCM_TSG_ID")
        
        # Validate credentials
        missing = []
        if not client_id:
            missing.append("SCM_CLIENT_ID")
        if not client_secret:
            missing.append("SCM_CLIENT_SECRET")
        if not tsg_id:
            missing.append("SCM_TSG_ID")
        
        if missing:
            error_msg = f"Missing required credentials: {', '.join(missing)}"
            self._log_error(error_msg)
            raise ConversionError(error_msg)
        
        self._log_success("All required credentials found")
        return client_id, client_secret, tsg_id

    def authenticate(self) -> None:
        """
        Authenticate with Strata Cloud Manager and initialize client.
        
        Raises:
            AuthenticationError: If authentication fails
            ConversionError: If client initialization fails
        """
        try:
            client_id, client_secret, tsg_id = self.load_credentials()
            
            logger.info("Initializing SCM client...")
            
            if self.dry_run:
                logger.info("DRY RUN MODE: Client initialization simulated")
                return
            
            # Initialize the client
            self.client = Scm(
                client_id=client_id,
                client_secret=client_secret,
                tsg_id=tsg_id,
                log_level="DEBUG" if logger.isEnabledFor(logging.DEBUG) else "INFO"
            )
            
            # Initialize managers
            self.address_manager = Address(self.client)
            self.address_group_manager = AddressGroup(self.client)
            self.tag_manager = Tag(self.client)
            self.folder_manager = Folder(self.client)
            
            # Test authentication with a simple API call
            try:
                folders = self.folder_manager.list(limit=1)
                self._log_success(f"Authentication successful - connected to TSG: {tsg_id[:8]}...")
                logger.debug(f"Test API call successful, found {len(folders)} folder(s)")
            except Exception as e:
                raise AuthenticationError(f"Authentication test failed: {e}")
                
        except AuthenticationError:
            raise
        except Exception as e:
            raise ConversionError(f"Failed to initialize client: {e}")

    def select_folder(self, folder_name: Optional[str] = None) -> str:
        """
        Select and validate the folder to work with.
        
        Args:
            folder_name: Pre-selected folder name, or None for interactive selection
            
        Returns:
            Selected folder name
            
        Raises:
            ConversionError: If folder selection fails or folder doesn't exist
        """
        self._log_section("FOLDER SELECTION")
        
        if self.dry_run:
            selected_folder = folder_name or "DryRun-Folder"
            logger.info(f"DRY RUN MODE: Using folder '{selected_folder}'")
            self.folder_name = selected_folder
            return selected_folder
        
        try:
            # Get available folders
            logger.info("Retrieving available folders...")
            folders = self.folder_manager.list()
            
            if not folders:
                raise ConversionError("No folders found in the environment")
            
            logger.info(f"Found {len(folders)} available folder(s)")
            
            # If folder_name provided, validate it exists
            if folder_name:
                folder_names = [f.name for f in folders]
                if folder_name not in folder_names:
                    raise ConversionError(f"Folder '{folder_name}' not found. Available: {', '.join(folder_names)}")
                self.folder_name = folder_name
                self._log_success(f"Using pre-selected folder: {folder_name}")
                return folder_name
            
            # Interactive folder selection
            print(f"\n{Colors.BRIGHT_BLUE}Available folders:{Colors.RESET}")
            for i, folder in enumerate(folders, 1):
                description = f" - {folder.description}" if hasattr(folder, 'description') and folder.description else ""
                print(f"  {i}. {folder.name}{description}")
            
            # Get user selection
            while True:
                try:
                    print(f"\n{Colors.CYAN}Select folder (1-{len(folders)}) or enter folder name:{Colors.RESET} ", end="")
                    selection = input().strip()
                    
                    # Try numeric selection first
                    try:
                        idx = int(selection) - 1
                        if 0 <= idx < len(folders):
                            selected_folder = folders[idx].name
                            break
                    except ValueError:
                        # Try name selection
                        folder_names = [f.name for f in folders]
                        if selection in folder_names:
                            selected_folder = selection
                            break
                        else:
                            print(f"{Colors.RED}Invalid selection. Please try again.{Colors.RESET}")
                            continue
                    
                    print(f"{Colors.RED}Invalid selection. Please enter a number between 1 and {len(folders)} or a valid folder name.{Colors.RESET}")
                    
                except KeyboardInterrupt:
                    print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.RESET}")
                    sys.exit(0)
            
            self.folder_name = selected_folder
            self._log_success(f"Selected folder: {selected_folder}")
            return selected_folder
            
        except Exception as e:
            raise ConversionError(f"Failed to select folder: {e}")

    def list_static_address_groups(self) -> List[Dict]:
        """
        List all static address groups in the selected folder.
        
        Returns:
            List of static address group information dictionaries
            
        Raises:
            ConversionError: If listing fails
        """
        logger.info(f"Retrieving static address groups from folder: {self.folder_name}")
        
        if self.dry_run:
            # Return mock data for dry run
            mock_groups = [
                {
                    'id': 'mock-group-1',
                    'name': 'Umbrella Global Allow List',
                    'description': 'Global allow list for Umbrella DNS filtering containing trusted domains',
                    'static_members': ['apple.com', 'microsoft.com', 'google.com'],
                    'member_count': 41,
                    'nested_groups': 0,
                    'tags': ['Production', 'DNS-Filter']
                },
                {
                    'id': 'mock-group-2', 
                    'name': 'GlobalWebDestAllow- IPs',
                    'description': 'IP addresses for globally allowed web destinations',
                    'static_members': ['1.1.1.1', '8.8.8.8', '104.193.137.35'],
                    'member_count': 847,
                    'nested_groups': 2,
                    'tags': ['Production', 'Web-Filter']
                },
                {
                    'id': 'mock-group-3',
                    'name': 'ADEM-Domains',
                    'description': 'ADEM monitoring domain names',
                    'static_members': ['adem-1', 'adem2', 'adem3'],
                    'member_count': 14,
                    'nested_groups': 0,
                    'tags': ['Monitoring']
                }
            ]
            logger.info(f"DRY RUN MODE: Found {len(mock_groups)} mock static address groups")
            return mock_groups
        
        try:
            # Get all address groups in the folder
            all_groups = self.address_group_manager.list(folder=self.folder_name)
            logger.info(f"Retrieved {len(all_groups)} total address groups")
            
            # Debug: Show summary of what we found  
            static_count = sum(1 for group in all_groups if hasattr(group, 'static') and group.static)
            logger.info(f"Summary: {static_count} static groups, {len(all_groups) - static_count} dynamic/empty groups")
            
            # Filter for static groups only
            static_groups = []
            logger.info(f"Processing all {len(all_groups)} groups to identify static groups...")
            
            for i, group in enumerate(all_groups, 1):
                # Check if group is static (has 'static' attribute with members)
                if hasattr(group, 'static') and group.static:
                    # For performance, don't validate individual address objects for large groups
                    # Just assume all static members are valid address objects
                    member_count = len(group.static)
                    nested_groups = 0  # We'll estimate this as 0 for simplicity
                    
                    group_info = {
                        'id': group.id,
                        'name': group.name,
                        'description': getattr(group, 'description', None),
                        'static_members': group.static[:10],  # Keep first 10 for reference
                        'member_count': member_count,
                        'nested_groups': nested_groups,
                        'tags': getattr(group, 'tag', [])
                    }
                    static_groups.append(group_info)
                    logger.debug(f"Added static group: {group.name} ({member_count} members)")
                else:
                    logger.debug(f"Skipping dynamic/empty group: {group.name}")
            
            logger.info(f"Found {len(static_groups)} static address groups (filtered from {len(all_groups)} total groups)")
            return static_groups
            
        except Exception as e:
            raise ConversionError(f"Failed to list address groups: {e}")

    def display_address_groups(self, groups: List[Dict]) -> None:
        """
        Display address groups in a simple list for selection.
        
        Args:
            groups: List of address group information dictionaries
        """
        if not groups:
            self._print_colored("No static address groups found.", Colors.YELLOW)
            return
        
        print(f"\n{Colors.BRIGHT_BLUE}Available Static Address Groups in folder '{self.folder_name}':{Colors.RESET}")
        
        for i, group in enumerate(groups, 1):
            # Display basic info: number, name, member count
            member_info = f"({group['member_count']} members"
            if group['nested_groups'] > 0:
                member_info += f", {group['nested_groups']} nested groups"
            member_info += ")"
            
            print(f"  {i}. {Colors.CYAN}{group['name']}{Colors.RESET} {Colors.YELLOW}{member_info}{Colors.RESET}")
            
            # Show description if available (single line, truncated)
            if group['description']:
                desc = group['description'][:80] + "..." if len(group['description']) > 80 else group['description']
                print(f"     {desc}")
                
        print()  # Empty line for spacing

    def select_address_group(self, groups: List[Dict]) -> Dict:
        """
        Allow user to select an address group for conversion.
        
        Args:
            groups: List of available address group dictionaries
            
        Returns:
            Selected address group dictionary
            
        Raises:
            ConversionError: If selection fails or is cancelled
        """
        if not groups:
            raise ConversionError("No address groups available for selection")
        
        self.display_address_groups(groups)
        
        # In non-interactive mode, return all groups
        if self.non_interactive:
            print(f"\n{Colors.BRIGHT_GREEN}Non-interactive mode: Processing all {len(groups)} address groups{Colors.RESET}")
            return groups  # Return all groups for batch processing
        
        print(f"\n{Colors.CYAN}Select an address group to convert:{Colors.RESET}")
        print(f"{Colors.YELLOW}Enter the number (1-{len(groups)}) or the full group name{Colors.RESET}")
        
        while True:
            try:
                selection = input(f"{Colors.CYAN}Selection: {Colors.RESET}").strip()
                
                if not selection:
                    print(f"{Colors.RED}Please enter a selection.{Colors.RESET}")
                    continue
                
                # Try numeric selection
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(groups):
                        selected_group = groups[idx]
                        break
                except ValueError:
                    # Try name selection
                    matching_groups = [g for g in groups if g['name'].lower() == selection.lower()]
                    if matching_groups:
                        selected_group = matching_groups[0]
                        break
                    else:
                        print(f"{Colors.RED}No group found with name '{selection}'. Please try again.{Colors.RESET}")
                        continue
                
                print(f"{Colors.RED}Invalid selection. Please enter a number between 1 and {len(groups)} or a valid group name.{Colors.RESET}")
                
            except KeyboardInterrupt:
                raise ConversionError("Selection cancelled by user")
        
        self._log_success(f"Selected address group: {selected_group['name']} ({selected_group['member_count']} members)")
        logger.debug(f"Selected group details: {selected_group}")
        return selected_group

    def sanitize_tag_name(self, group_name: str) -> str:
        """
        Sanitize group name for use as a tag.
        
        Args:
            group_name: Original address group name
            
        Returns:
            Sanitized tag name
        """
        # Convert to lowercase and replace special characters with hyphens
        sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '-', group_name.lower())
        # Remove multiple consecutive hyphens
        sanitized = re.sub(r'-+', '-', sanitized)
        # Remove leading/trailing hyphens
        sanitized = sanitized.strip('-')
        
        # Ensure it starts with a letter (tag naming requirement)
        if sanitized and not sanitized[0].isalpha():
            sanitized = f"converted-{sanitized}"
        
        # Add prefix for converted groups
        tag_name = f"converted-ag-{sanitized}"
        
        # Ensure reasonable length (max 32 characters for tags)
        if len(tag_name) > 32:
            # Keep prefix and truncate the rest
            max_suffix_len = 32 - len("converted-ag-")
            sanitized = sanitized[:max_suffix_len]
            tag_name = f"converted-ag-{sanitized}"
        
        return tag_name

    def check_tag_conflicts(self, tag_name: str) -> bool:
        """
        Check if the proposed tag name already exists.
        
        Args:
            tag_name: Proposed tag name
            
        Returns:
            True if tag exists, False otherwise
        """
        if self.dry_run:
            logger.info(f"DRY RUN MODE: Checking for tag conflicts with '{tag_name}'")
            return False  # Assume no conflicts in dry run
        
        try:
            existing_tags = self.tag_manager.list(folder=self.folder_name)
            tag_names = [tag.name for tag in existing_tags]
            return tag_name in tag_names
        except Exception as e:
            logger.warning(f"Could not check for tag conflicts: {e}")
            return False  # Assume no conflicts if we can't check

    def generate_unique_tag_name(self, base_tag_name: str) -> str:
        """
        Generate a unique tag name by adding timestamp if needed.
        
        Args:
            base_tag_name: Base tag name to make unique
            
        Returns:
            Unique tag name
        """
        if not self.check_tag_conflicts(base_tag_name):
            return base_tag_name
        
        # Add timestamp to make it unique
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        unique_name = f"{base_tag_name}-{timestamp}"
        
        # Ensure it still fits length requirements
        if len(unique_name) > 32:
            # Truncate base name to fit timestamp
            max_base_len = 32 - len(f"-{timestamp}")
            truncated_base = base_tag_name[:max_base_len]
            unique_name = f"{truncated_base}-{timestamp}"
        
        logger.info(f"Tag name conflict detected, using unique name: {unique_name}")
        return unique_name
    
    # Continue with more methods...
    def create_conversion_tag(self, tag_name: str) -> bool:
        """
        Create the tag that will be used for the dynamic group filter.
        
        Args:
            tag_name: Name of the tag to create
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Creating conversion tag: {tag_name}")
        
        if self.dry_run:
            logger.info(f"DRY RUN MODE: Would create tag '{tag_name}'")
            self.created_tags.append(tag_name)
            return True
        
        try:
            tag_config = {
                'name': tag_name,
                'folder': self.folder_name,
                'color': 'blue',  # Use blue color for conversion tags
                'comments': f'Auto-generated tag for address group conversion at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
            }
            
            created_tag = self.tag_manager.create(tag_config)
            self.created_tags.append(tag_name)
            self._log_success(f"Created conversion tag: {created_tag.name}")
            logger.debug(f"Tag ID: {created_tag.id}")
            return True
            
        except NameNotUniqueError:
            # Tag already exists - this shouldn't happen due to our conflict checking
            logger.warning(f"Tag '{tag_name}' already exists, will use existing tag")
            return True
        except Exception as e:
            self._log_error(f"Failed to create tag '{tag_name}'", e)
            return False


    def create_backup(self, group_info: Dict) -> bool:
        """
        Create a backup of the current configuration before making changes.
        
        Args:
            group_info: Information about the group being converted
            
        Returns:
            True if backup successful, False otherwise
        """
        self._log_section("CREATING CONFIGURATION BACKUP")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"scm_backup_{self.folder_name}_{timestamp}.json"
        
        logger.info(f"Creating backup: {backup_file}")
        
        if self.dry_run:
            logger.info("DRY RUN MODE: Backup creation simulated")
            self.backup_data = {
                'metadata': {
                    'timestamp': timestamp,
                    'folder': self.folder_name,
                    'group_name': group_info['name'],
                    'group_id': group_info['id'],
                    'conversion_tag': None  # Will be set later
                },
                'group_info': group_info,
                'backup_file': backup_file
            }
            return True
        
        try:
            backup_data = {
                'metadata': {
                    'timestamp': timestamp,
                    'folder': self.folder_name,
                    'group_name': group_info['name'],
                    'group_id': group_info['id'],
                    'conversion_tag': None  # Will be set later
                },
                'original_group': {},
                'address_objects': {},
                'existing_tags': []
            }
            
            # Get the full group details
            logger.info("Backing up address group configuration...")
            original_group = self.address_group_manager.get(group_info['id'])
            backup_data['original_group'] = {
                'id': original_group.id,
                'name': original_group.name,
                'description': getattr(original_group, 'description', None),
                'folder': getattr(original_group, 'folder', None),
                'static': getattr(original_group, 'static', []),
                'tag': getattr(original_group, 'tag', [])
            }
            
            # Backup address objects that will be modified
            logger.info("Backing up address objects...")
            for member_name in group_info['static_members']:
                try:
                    address_obj = self.address_manager.fetch(name=member_name, folder=self.folder_name)
                    backup_data['address_objects'][member_name] = {
                        'id': address_obj.id,
                        'name': address_obj.name,
                        'description': getattr(address_obj, 'description', None),
                        'tag': getattr(address_obj, 'tag', []),
                        'folder': getattr(address_obj, 'folder', None)
                    }
                    
                    # Add type-specific attributes
                    for attr in ['ip_netmask', 'ip_range', 'fqdn', 'ip_wildcard']:
                        if hasattr(address_obj, attr):
                            value = getattr(address_obj, attr)
                            if value:
                                backup_data['address_objects'][member_name][attr] = value
                                break
                    
                except Exception as e:
                    logger.warning(f"Could not backup address object '{member_name}': {e}")
            
            # Backup existing tags in folder
            logger.info("Backing up existing tags...")
            try:
                existing_tags = self.tag_manager.list(folder=self.folder_name)
                backup_data['existing_tags'] = [
                    {'name': tag.name, 'id': tag.id, 'color': getattr(tag, 'color', None)}
                    for tag in existing_tags
                ]
            except Exception as e:
                logger.warning(f"Could not backup existing tags: {e}")
            
            # Write backup to file
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            self.backup_data = backup_data
            self.backup_data['backup_file'] = backup_file
            
            self._log_success(f"Backup created successfully: {backup_file}")
            logger.info(f"Backup includes {len(backup_data['address_objects'])} address objects and {len(backup_data['existing_tags'])} existing tags")
            
            return True
            
        except Exception as e:
            self._log_error(f"Failed to create backup", e)
            return False

    def batch_process_with_retry(self, objects: List, operation_func, operation_name: str, max_retries: int = 3) -> Tuple[List, List]:
        """
        Process objects in batches with retry logic and rate limiting.
        
        Args:
            objects: List of objects to process
            operation_func: Function to apply to each object
            operation_name: Name of the operation for logging
            max_retries: Maximum number of retries for failed operations
            
        Returns:
            Tuple of (successful_objects, failed_objects)
        """
        logger.info(f"Starting batch processing: {operation_name}")
        logger.info(f"Total objects: {len(objects)}, Batch size: {self.batch_size}")
        
        successful = []
        failed = []
        
        # Process in batches
        for i in range(0, len(objects), self.batch_size):
            batch = objects[i:i + self.batch_size]
            batch_num = (i // self.batch_size) + 1
            total_batches = (len(objects) + self.batch_size - 1) // self.batch_size
            
            logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} objects)")
            
            # Process each object in the batch
            for obj in batch:
                retry_count = 0
                while retry_count <= max_retries:
                    try:
                        result = operation_func(obj)
                        successful.append(result)
                        break
                    except requests.exceptions.HTTPError as e:
                        if e.response and e.response.status_code == 429:
                            # Rate limiting - implement exponential backoff
                            retry_after = int(e.response.headers.get('Retry-After', 2 ** retry_count))
                            logger.warning(f"Rate limited, waiting {retry_after} seconds before retry")
                            if not self.dry_run:
                                time.sleep(retry_after)
                            retry_count += 1
                        else:
                            logger.error(f"HTTP error processing object: {e}")
                            failed.append({'object': obj, 'error': str(e)})
                            break
                    except Exception as e:
                        logger.error(f"Error processing object: {e}")
                        if retry_count < max_retries:
                            retry_count += 1
                            wait_time = 2 ** retry_count
                            logger.info(f"Retrying in {wait_time} seconds... (attempt {retry_count + 1}/{max_retries + 1})")
                            if not self.dry_run:
                                time.sleep(wait_time)
                        else:
                            failed.append({'object': obj, 'error': str(e)})
                            break
            
            # Progress reporting
            processed = len(successful) + len(failed)
            if processed % 25 == 0 or processed == len(objects):
                logger.info(f"Progress: {processed}/{len(objects)} objects processed ({processed/len(objects)*100:.1f}%)")
            
            # Small delay between batches to avoid overwhelming the API
            if batch_num < total_batches and not self.dry_run:
                time.sleep(0.5)
        
        logger.info(f"Batch processing complete: {len(successful)} successful, {len(failed)} failed")
        return successful, failed

    def tag_address_objects(self, group_info: Dict, tag_name: str) -> bool:
        """
        Tag all address objects in the static group.
        
        Args:
            group_info: Information about the address group
            tag_name: Name of the tag to apply
            
        Returns:
            True if all objects tagged successfully, False otherwise
        """
        self._log_section("TAGGING ADDRESS OBJECTS")
        
        members = group_info['static_members']
        logger.info(f"Tagging {len(members)} address objects with tag: {tag_name}")
        
        if self.dry_run:
            logger.info("DRY RUN MODE: Address object tagging simulated")
            self.processed_objects = members.copy()
            self.conversion_stats['objects_tagged'] = len(members)
            return True
        
        def tag_address_object(member_name: str) -> str:
            """Tag a single address object."""
            try:
                # Get the address object
                address_obj = self.address_manager.fetch(name=member_name, folder=self.folder_name)
                
                # Get current tags
                current_tags = getattr(address_obj, 'tag', []) or []
                
                # Check if tag already exists
                if tag_name in current_tags:
                    logger.debug(f"Tag '{tag_name}' already exists on {member_name}")
                    return member_name
                
                # Add the new tag
                new_tags = current_tags + [tag_name]
                address_obj.tag = new_tags
                
                # Update the address object
                updated_obj = self.address_manager.update(address_obj)
                logger.debug(f"Tagged address object: {updated_obj.name}")
                
                return member_name
                
            except Exception as e:
                raise Exception(f"Failed to tag {member_name}: {e}")
        
        # Process in batches
        successful, failed = self.batch_process_with_retry(
            members, tag_address_object, f"tagging with '{tag_name}'"
        )
        
        self.processed_objects = successful
        self.conversion_stats['objects_tagged'] = len(successful)
        
        if failed:
            self._log_error(f"Failed to tag {len(failed)} address objects")
            for failure in failed:
                logger.error(f"  - {failure['object']}: {failure['error']}")
            return False
        else:
            self._log_success(f"Successfully tagged all {len(successful)} address objects")
            return True

    def convert_to_dynamic_group(self, group_info: Dict, tag_name: str) -> bool:
        """
        Convert the static address group to dynamic using the tag filter.
        
        Args:
            group_info: Information about the address group
            tag_name: Tag name to use in the dynamic filter
            
        Returns:
            True if conversion successful, False otherwise
        """
        self._log_section("CONVERTING TO DYNAMIC GROUP")
        
        logger.info(f"Converting group '{group_info['name']}' to dynamic")
        logger.info(f"Filter will be: '{tag_name}'")
        
        if self.dry_run:
            logger.info("DRY RUN MODE: Group conversion simulated")
            self.conversion_stats['groups_converted'] = 1
            return True
        
        try:
            # Get the current group
            group = self.address_group_manager.get(group_info['id'])
            
            # Create the new dynamic configuration
            # Remove static members and add dynamic filter
            if hasattr(group, 'static'):
                delattr(group, 'static')
            
            # Set the dynamic filter
            group.dynamic = {'filter': f"'{tag_name}'"}
            
            # Update description to indicate conversion
            original_desc = getattr(group, 'description', '') or ''
            conversion_note = f" [Converted from static to dynamic on {datetime.now().strftime('%Y-%m-%d')}]"
            
            if len(original_desc + conversion_note) <= 255:  # Assuming max description length
                group.description = original_desc + conversion_note
            else:
                group.description = conversion_note
            
            # Perform the update
            updated_group = self.address_group_manager.update(group)
            
            self.conversion_stats['groups_converted'] = 1
            self._log_success(f"Successfully converted group to dynamic: {updated_group.name}")
            logger.debug(f"New filter: {updated_group.dynamic.filter}")
            
            return True
            
        except Exception as e:
            self._log_error(f"Failed to convert group to dynamic", e)
            return False

    def commit_changes(self) -> bool:
        """
        Commit all changes to Strata Cloud Manager.
        
        Returns:
            True if commit successful, False otherwise
        """
        self._log_section("COMMITTING CHANGES")
        
        if self.dry_run:
            logger.info("DRY RUN MODE: Change commit simulated")
            return True
        
        try:
            logger.info("Committing configuration changes...")
            
            # Create commit description
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            admin_name = os.environ.get('USER', 'automated-script')
            
            commit_description = (
                f"Automated conversion: Static to dynamic address group - {timestamp}\n"
                f"Converted groups: {self.conversion_stats['groups_converted']}\n"
                f"Tagged objects: {self.conversion_stats['objects_tagged']}\n"
                f"Initiated by: {admin_name}"
            )
            
            # Perform the commit using the client's commit method
            commit_data = {
                'folders': [self.folder_name],
                'description': commit_description,
                'admin': admin_name
            }
            
            logger.info(f"Committing changes for folder: {self.folder_name}")
            job_result = self.client.commit(folders=[self.folder_name], description=commit_description)
            
            if hasattr(job_result, 'id'):
                job_id = job_result.id
                logger.info(f"Commit job started with ID: {job_id}")
                
                # Wait for job completion using client's wait_for_job method
                try:
                    final_status = self.client.wait_for_job(job_id, timeout=600)  # 10 minutes
                    
                    if hasattr(final_status, 'success') and final_status.success:
                        self._log_success("Configuration changes committed successfully")
                        return True
                    else:
                        error_msg = getattr(final_status, 'message', 'Unknown error')
                        self._log_error(f"Commit job failed: {error_msg}")
                        return False
                        
                except Exception as wait_error:
                    logger.warning(f"Error waiting for job completion: {wait_error}")
                    logger.info(f"Commit job {job_id} may still be running - check SCM interface")
                    return False
            else:
                # Immediate success (no job created)
                self._log_success("Configuration changes committed successfully")
                return True
            
        except Exception as e:
            self._log_error("Failed to commit changes", e)
            logger.info("You may need to commit changes manually in the SCM interface")
            return False

    def rollback_changes(self) -> bool:
        """
        Rollback changes using the backup data.
        
        Returns:
            True if rollback successful, False otherwise
        """
        self._log_section("ROLLING BACK CHANGES")
        
        if not self.backup_data:
            self._log_error("No backup data available for rollback")
            return False
        
        if self.dry_run:
            logger.info("DRY RUN MODE: Rollback simulated")
            return True
        
        rollback_successful = True
        
        try:
            # Rollback address object tags
            logger.info("Rolling back address object tags...")
            
            for member_name, original_data in self.backup_data.get('address_objects', {}).items():
                try:
                    address_obj = self.address_manager.get(original_data['id'])
                    address_obj.tag = original_data.get('tag', [])
                    self.address_manager.update(address_obj)
                    logger.debug(f"Restored tags for address object: {member_name}")
                except Exception as e:
                    logger.error(f"Failed to rollback address object {member_name}: {e}")
                    rollback_successful = False
            
            # Rollback address group configuration
            logger.info("Rolling back address group configuration...")
            
            try:
                original_group = self.backup_data['original_group']
                group = self.address_group_manager.get(original_group['id'])
                
                # Restore original configuration
                group.description = original_group['description']
                group.static = original_group['static']
                group.tag = original_group['tag']
                
                # Remove dynamic filter if it exists
                if hasattr(group, 'dynamic'):
                    delattr(group, 'dynamic')
                
                self.address_group_manager.update(group)
                logger.info("Restored original address group configuration")
                
            except Exception as e:
                logger.error(f"Failed to rollback address group: {e}")
                rollback_successful = False
            
            # Remove created tags
            logger.info("Removing created conversion tags...")
            
            for tag_name in self.created_tags:
                try:
                    # Find the tag
                    tags = self.tag_manager.list(folder=self.folder_name)
                    for tag in tags:
                        if tag.name == tag_name:
                            self.tag_manager.delete(tag.id)
                            logger.debug(f"Removed conversion tag: {tag_name}")
                            break
                except Exception as e:
                    logger.error(f"Failed to remove tag {tag_name}: {e}")
                    rollback_successful = False
            
            if rollback_successful:
                self._log_success("Rollback completed successfully")
            else:
                self._log_warning("Rollback completed with some errors - check logs for details")
            
            return rollback_successful
            
        except Exception as e:
            self._log_error("Failed to perform rollback", e)
            return False

    def generate_final_report(self) -> None:
        """Generate and display the final conversion report."""
        self._log_section("CONVERSION REPORT")
        
        # Calculate execution time
        if self.conversion_stats['start_time'] and self.conversion_stats['end_time']:
            execution_time = self.conversion_stats['end_time'] - self.conversion_stats['start_time']
            minutes, seconds = divmod(execution_time, 60)
            time_str = f"{int(minutes)}m {seconds:.1f}s"
        else:
            time_str = "Unknown"
        
        # Calculate performance metrics
        total_objects = self.conversion_stats['objects_tagged']
        if execution_time > 0 and total_objects > 0:
            objects_per_minute = (total_objects / execution_time) * 60
            performance_str = f"{objects_per_minute:.1f} objects/minute"
        else:
            performance_str = "N/A"
        
        # Display report
        print(f"\n{Colors.BRIGHT_CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'CONVERSION SUMMARY':^60}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.RESET}")
        
        status_color = Colors.BRIGHT_GREEN if self.conversion_stats['errors'] == 0 else Colors.BRIGHT_YELLOW
        status_text = "SUCCESS" if self.conversion_stats['errors'] == 0 else "COMPLETED WITH ERRORS"
        
        print(f"Status: {status_color}{status_text}{Colors.RESET}")
        print(f"Execution Time: {Colors.CYAN}{time_str}{Colors.RESET}")
        print(f"Folder: {Colors.CYAN}{self.folder_name}{Colors.RESET}")
        print()
        print(f"Objects Tagged: {Colors.BRIGHT_GREEN}{self.conversion_stats['objects_tagged']}{Colors.RESET}")
        print(f"Groups Converted: {Colors.BRIGHT_GREEN}{self.conversion_stats['groups_converted']}{Colors.RESET}")
        print(f"Errors Encountered: {Colors.RED if self.conversion_stats['errors'] > 0 else Colors.GREEN}{self.conversion_stats['errors']}{Colors.RESET}")
        print(f"Performance: {Colors.CYAN}{performance_str}{Colors.RESET}")
        print()
        
        if self.backup_data.get('backup_file'):
            print(f"Backup File: {Colors.CYAN}{self.backup_data['backup_file']}{Colors.RESET}")
        
        print(f"Log File: {Colors.CYAN}{self.log_file}{Colors.RESET}")
        
        if self.created_tags:
            print(f"Conversion Tags Created: {Colors.CYAN}{', '.join(self.created_tags)}{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.RESET}")
        
        # Log the summary
        logger.info(f"Conversion completed - Status: {status_text}")
        logger.info(f"Statistics: {self.conversion_stats['objects_tagged']} objects tagged, {self.conversion_stats['groups_converted']} groups converted")
        logger.info(f"Execution time: {time_str}, Performance: {performance_str}")

    def run_conversion(self, folder_name: Optional[str] = None) -> int:
        """
        Run the complete conversion process.
        
        Args:
            folder_name: Optional folder name to use (skip selection if provided)
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            self.conversion_stats['start_time'] = time.time()
            
            # Step 1: Authenticate
            self.authenticate()
            
            # Step 2: Select folder
            self.select_folder(folder_name)
            
            # Step 3: List static address groups
            static_groups = self.list_static_address_groups()
            
            if not static_groups:
                self._print_colored("No static address groups found for conversion.", Colors.YELLOW)
                return 0
            
            # Step 4: Select address group(s)
            selected_groups = self.select_address_group(static_groups)
            
            # Handle both single group (interactive) and multiple groups (non-interactive)
            if not isinstance(selected_groups, list):
                selected_groups = [selected_groups]  # Convert single group to list
            
            # Step 5: Process each group
            for i, selected_group in enumerate(selected_groups, 1):
                print(f"\n{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}")
                print(f"{Colors.BRIGHT_BLUE}Processing Group {i}/{len(selected_groups)}: {selected_group['name']}{Colors.RESET}")
                print(f"{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}")
                
                # Generate and confirm tag name
                base_tag_name = self.sanitize_tag_name(selected_group['name'])
                tag_name = self.generate_unique_tag_name(base_tag_name)
                
                print(f"\n{Colors.BRIGHT_BLUE}Conversion Plan:{Colors.RESET}")
                print(f"Selected Group: {Colors.CYAN}{selected_group['name']}{Colors.RESET}")
                print(f"Objects to Tag: {Colors.CYAN}{selected_group['member_count']}{Colors.RESET}")
                print(f"Conversion Tag: {Colors.CYAN}{tag_name}{Colors.RESET}")
                print(f"New Dynamic Filter: {Colors.CYAN}'{tag_name}'{Colors.RESET}")
                
                if not self.dry_run and not self.non_interactive:
                    print(f"\n{Colors.YELLOW}This will modify {selected_group['member_count']} address objects and 1 address group.{Colors.RESET}")
                    confirmation = input(f"{Colors.CYAN}Proceed with tagging operation? (y/N): {Colors.RESET}").strip().lower()
                    if confirmation not in ['y', 'yes']:
                        self._print_colored("Operation cancelled by user.", Colors.YELLOW)
                        continue  # Skip this group and continue with next
                
                # Step 6: Create backup
                if not self.create_backup(selected_group):
                    self._log_error(f"Backup creation failed for group {selected_group['name']} - skipping")
                    continue
                
                # Store tag name in backup metadata
                if self.backup_data:
                    self.backup_data['metadata']['conversion_tag'] = tag_name
                
                # Step 7: Create conversion tag
                if not self.create_conversion_tag(tag_name):
                    self._log_error(f"Failed to create conversion tag for {selected_group['name']} - skipping")
                    continue
                
                # Step 8: Tag address objects
                if not self.tag_address_objects(selected_group, tag_name):
                    self._log_error(f"Failed to tag all address objects for {selected_group['name']}")
                    
                    if not self.dry_run and not self.non_interactive:
                        print(f"\n{Colors.RED}Tagging failed. Would you like to rollback changes? (Y/n): {Colors.RESET}", end="")
                        rollback_choice = input().strip().lower()
                        if rollback_choice not in ['n', 'no']:
                            self.rollback_changes()
                    
                    self.conversion_stats['errors'] += 1
                    continue
                
                # Step 9: Convert to dynamic group (second confirmation)
                if not self.dry_run and not self.non_interactive:
                    print(f"\n{Colors.BRIGHT_GREEN}Tagging completed successfully!{Colors.RESET}")
                    print(f"{Colors.YELLOW}Ready to convert the group from static to dynamic.{Colors.RESET}")
                    confirmation = input(f"{Colors.CYAN}Proceed with group conversion? (y/N): {Colors.RESET}").strip().lower()
                    if confirmation not in ['y', 'yes']:
                        self._print_colored("Group conversion cancelled. Objects remain tagged.", Colors.YELLOW)
                        continue
                
                # Step 10: Convert group to dynamic
                if not self.convert_to_dynamic_group(selected_group, tag_name):
                    self._log_error(f"Failed to convert group {selected_group['name']} to dynamic")
                    
                    if not self.dry_run and not self.non_interactive:
                        print(f"\n{Colors.RED}Conversion failed. Would you like to rollback all changes? (Y/n): {Colors.RESET}", end="")
                        rollback_choice = input().strip().lower()
                        if rollback_choice not in ['n', 'no']:
                            self.rollback_changes()
                    
                    self.conversion_stats['errors'] += 1
                    continue
                
                # Step 11: Commit changes
                if not self.commit_changes():
                    self._log_warning(f"Failed to commit changes automatically for group {selected_group['name']}")
                    logger.info("You may need to commit changes manually in the SCM interface")
                # Don't consider this a fatal error
                
                self._log_success(f"Successfully converted group {selected_group['name']} to dynamic")
                self.conversion_stats['groups_converted'] += 1
            
            # Final summary
            self.conversion_stats['end_time'] = time.time()
            
            # Step 12: Generate final report
            self.generate_final_report()
            
            return 0
            
        except KeyboardInterrupt:
            self._print_colored("\nOperation cancelled by user.", Colors.YELLOW)
            return 1
        except ConversionError as e:
            self._log_error(f"Conversion error: {e}")
            self.conversion_stats['errors'] += 1
            return 2
        except Exception as e:
            self._log_error(f"Unexpected error: {e}")
            logger.exception("Full exception details:")
            self.conversion_stats['errors'] += 1
            return 3
        finally:
            if self.conversion_stats.get('start_time') and not self.conversion_stats.get('end_time'):
                self.conversion_stats['end_time'] = time.time()


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Convert Strata Cloud Manager static address groups to dynamic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s --folder Texas           # Pre-select folder
  %(prog)s --dry-run --verbose      # Test run with debug output
  %(prog)s --batch-size 25          # Use smaller batch size
  %(prog)s --skip-ssl-verify        # Bypass SSL verification (dev/test only)

Environment Variables:
  SCM_CLIENT_ID       OAuth2 client ID (required)
  SCM_CLIENT_SECRET   OAuth2 client secret (required) 
  SCM_TSG_ID          Tenant Service Group ID (required)

Exit Codes:
  0 - Success
  1 - User cancellation
  2 - Conversion/authentication error
  3 - Unexpected error

Security Warning:
  --skip-ssl-verify should ONLY be used in development/testing environments
  with self-signed certificates or corporate proxies. NEVER use in production!
        """
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate all operations without making changes'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true', 
        help='Enable debug-level logging to console'
    )
    
    parser.add_argument(
        '--folder',
        type=str,
        help='Pre-select folder name (skip folder selection prompt)'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Number of objects to process in each batch (default: 50)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Process all address groups without prompting (non-interactive mode)'
    )
    
    parser.add_argument(
        '--skip-ssl-verify',
        action='store_true',
        help='Skip SSL certificate verification (DEVELOPMENT/TESTING ONLY - NOT FOR PRODUCTION)'
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the script.
    
    Returns:
        Exit code
    """
    try:
        args = parse_arguments()
        
        # Validate batch size
        if args.batch_size < 1 or args.batch_size > 1000:
            print(f"{Colors.RED}Error: Batch size must be between 1 and 1000{Colors.RESET}")
            return 2
        
        # Initialize converter
        converter = SCMAddressGroupConverter(
            dry_run=args.dry_run,
            verbose=args.verbose,
            batch_size=args.batch_size,
            skip_ssl_verify=args.skip_ssl_verify
        )
        
        # Set non-interactive mode if requested
        converter.non_interactive = getattr(args, 'all', False)
        
        # Print header
        print(f"{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'Strata Cloud Manager Address Group Converter':^70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}")
        
        if args.dry_run:
            print(f"{Colors.BRIGHT_YELLOW}{'DRY RUN MODE - No changes will be made':^70}{Colors.RESET}")
        
        if args.skip_ssl_verify:
            print(f"{Colors.RED}{'⚠️  SSL VERIFICATION DISABLED - DEVELOPMENT/TESTING ONLY ⚠️':^70}{Colors.RESET}")
        
        print()
        
        # Run conversion
        exit_code = converter.run_conversion(args.folder)
        
        return exit_code
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.RESET}")
        return 1
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {e}{Colors.RESET}")
        return 3


if __name__ == "__main__":
    sys.exit(main())