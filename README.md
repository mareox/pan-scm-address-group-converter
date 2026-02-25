# SCM Address Group Converter

Convert static address groups to dynamic address groups in Palo Alto Networks Strata Cloud Manager (SCM).

## Overview

This tool automates the conversion of static address groups (potentially with 1000+ objects) to dynamic ones by:

1. **Tagging** all address objects within a static group with a conversion-specific tag
2. **Converting** the static group to dynamic using the new tag as a filter
3. **Backing up** the original configuration for rollback capability

## Features

- **OAuth 2.0 Authentication** -- Secure API access using client credentials
- **Single Folder Operation** -- Process one folder at a time for better control
- **Batch Processing** -- Handle large groups efficiently (configurable batch size)
- **Dry Run Mode** -- Test all operations without making changes
- **Configuration Backup** -- Complete backup before any changes with rollback capability
- **Progress Reporting** -- Real-time progress updates during processing
- **Retry Logic** -- Exponential backoff for rate limits and transient errors

## Requirements

- Python 3.10+
- Network access to Strata Cloud Manager APIs
- Valid SCM service account credentials

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/mareox/pan-scm-address-group-converter.git
cd pan-scm-address-group-converter
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
```

### Using pip

```bash
git clone https://github.com/mareox/pan-scm-address-group-converter.git
cd pan-scm-address-group-converter
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Set up credentials

```bash
cp .env.example .env
# Edit .env with your actual credentials
```

## Configuration

Create a `.env` file with your Strata Cloud Manager credentials:

```bash
SCM_CLIENT_ID=your_client_id_here
SCM_CLIENT_SECRET=your_client_secret_here
SCM_TSG_ID=your_tenant_service_group_id_here
```

### Obtaining Credentials

1. Log into your Strata Cloud Manager instance
2. Navigate to **Settings** > **Service Accounts**
3. Create a new service account or use an existing one
4. Note the **Client ID**, **Client Secret**, and **TSG ID**
5. Ensure the service account has appropriate permissions for the target folder

## Usage

### Interactive Mode (Recommended)

```bash
python scm_address_group_converter.py
```

This will:
1. Authenticate with SCM
2. Display available folders for selection
3. List static address groups in the selected folder
4. Guide you through group selection and conversion

### Command-Line Options

```bash
# Test run without making changes
python scm_address_group_converter.py --dry-run --verbose

# Pre-select folder to skip selection prompt
python scm_address_group_converter.py --folder "Texas"

# Use smaller batch size for better control
python scm_address_group_converter.py --batch-size 25

# Skip SSL verification (development/testing environments only)
python scm_address_group_converter.py --skip-ssl-verify --dry-run

# Fully automated with pre-selected folder
python scm_address_group_converter.py --folder "Production" --batch-size 50
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--dry-run` | Simulate operations without making changes | False |
| `--verbose` | Enable debug-level logging to console | False |
| `--folder FOLDER` | Pre-select folder name (skip selection prompt) | None |
| `--batch-size N` | Objects to process per batch (1-1000) | 50 |
| `--skip-ssl-verify` | Skip SSL certificate verification | False |

## Workflow

The tool follows a systematic process:

1. **Authentication** -- Load credentials and initialize the SCM client
2. **Folder Selection** -- Display available folders, allow selection by number or name
3. **Group Discovery** -- List all static address groups in the folder, filter out dynamic and nested groups
4. **Group Selection** -- Display groups in a formatted table with member counts
5. **Tag Generation** -- Sanitize group name into tag format (`converted-ag-{name}`), resolve conflicts
6. **Backup** -- Save original group configuration and address object tags to a timestamped JSON file
7. **Tag Creation** -- Create the conversion tag in SCM
8. **Object Tagging** -- Tag all address objects in configurable batches with progress reporting
9. **Group Conversion** -- Convert the static group to dynamic with the tag as the filter
10. **Commit** -- Commit all changes to SCM and monitor job status
11. **Reporting** -- Display conversion summary with performance metrics

## Example Output

```
======================================================================
                Strata Cloud Manager Address Group Converter
======================================================================

======================================================================
  FOLDER SELECTION
======================================================================
Available folders:
  1. Texas - Production environment
  2. California - Development environment

Selection: 1

Static Address Groups in folder 'Texas':
No.  Name                          Members  Description
-------------------------------------------------------------------
1    Web-Servers-Static           156      Production web servers
2    Employee-Networks-Static     1247     Employee network ranges

Select an address group to convert: 2

Conversion Plan:
Selected Group: Employee-Networks-Static
Objects to Tag: 1247
Conversion Tag: converted-ag-employee-networks-static

Proceed with tagging operation? (y/N): y

======================================================================
  TAGGING ADDRESS OBJECTS
======================================================================
Processing batch 1/25 (50 objects)
...
Progress: 1247/1247 objects processed (100%)

Proceed with group conversion? (y/N): y

======================================================================
  CONVERSION SUMMARY
======================================================================
Status: SUCCESS
Objects Tagged: 1247
Groups Converted: 1
Errors: 0
Performance: 275.2 objects/minute
Backup: scm_backup_Texas_20250107_143022.json
```

## Error Handling

The tool handles common failure scenarios:

- **Authentication failures** -- Clear error messages with guidance to check credentials
- **Rate limiting** -- Automatic retry with exponential backoff
- **Object not found** -- Skip missing objects with warnings
- **Rollback** -- If tagging fails mid-way, restore original object tags from backup

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | User cancellation |
| 2 | Authentication or conversion error |
| 3 | Unexpected error |

## Performance Guidelines

| Environment Size | Recommended Batch Size |
|-----------------|----------------------|
| Small (< 100 objects) | `--batch-size 25` |
| Medium (100-500 objects) | `--batch-size 50` (default) |
| Large (> 500 objects) | `--batch-size 75` |

Expected throughput: **200-400 objects/minute** depending on network latency and API load.

## Troubleshooting

**Missing credentials** -- Verify `.env` file exists and contains `SCM_CLIENT_ID`, `SCM_CLIENT_SECRET`, `SCM_TSG_ID`.

**Authentication failed** -- Check that client ID, secret, and TSG ID are correct and the service account is active.

**Rate limited** -- The tool handles this automatically. Reduce `--batch-size` if it happens frequently.

**SSL errors** -- For environments with self-signed certificates or corporate proxies, use `--skip-ssl-verify`. Do not use this in production.

**Commit timeout** -- Large commits may take longer. Check the SCM interface manually.

**Address object not found** -- Verify objects exist in the folder and are not nested address groups.

## Security Notes

- Never commit `.env` files with real credentials
- Use service accounts with minimal required permissions
- Backup files contain configuration data -- store them securely
- The `--skip-ssl-verify` flag should only be used in development/testing environments

## License

MIT
