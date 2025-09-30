
# WSO2 Change Endpoint Utility

> This directory is part of the **wso2 cicd scripts** repository. It provides a utility for updating API endpoints in WSO2 API Manager as part of automated CI/CD workflows.

This subproject provides a command-line tool to update the endpoint of an API in a WSO2 API Manager environment. It automates the process of selecting an API, choosing a new service endpoint, updating the API configuration, and managing API revisions and deployments. It is intended to be used as part of the broader automation and CI/CD scripts in the main repository.

# Features
- Authenticate with WSO2 API Manager using DCR and OAuth2
- List available APIs and services
- Update the endpoint URL of a selected API
- Manage API revisions: create, deploy, undeploy, and delete
- Interactive CLI prompts for safe and flexible operation

# Requirements
- Python 3.6+
- `requests` library

# Setup
1. **Clone the repository** and navigate to the project directory.
2. **Configure API Manager access:**
   - Edit `config.ini` with your WSO2 API Manager URLs and credentials.
3. **Install dependencies:**
   - The script checks for the `requests` library. Install it if needed:
     ```bash
     pip install requests
     ```

# Usage
Run the script using the provided shell wrapper:

```bash
./run.sh
```

Or directly with Python:

```bash
python3 update_endpoint.py
```

You will be prompted to select an API and a new service endpoint. The script will update the API's endpoint configuration and manage revisions as needed.

# Configuration
Edit `config.ini` to set:
- API Manager URLs (base, DCR, token)
- Admin credentials
- Required scopes
- Service catalog URL and authentication
- SSL verification

# Notes
- The script is interactive and will prompt for confirmation before making changes.
- Revision and deployment management is included for safe updates.
- Some messages and prompts are in Persian (Farsi).

## License
This subproject is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
