# Intrusion Detection System (IDS) Documentation

## Table of Contents
1. Introduction
2. Installation
3. Configuration
4. Usage
5. API Reference
6. Troubleshooting
7. Contributing
8. License

## 1. Introduction
Welcome to the Intrusion Detection System (IDS) documentation. This IDS monitors network traffic, identifies potential threats, and provides alerts and reports to the cyber defense team. This document will guide you through the installation, configuration, usage, and maintenance of the IDS.

## 2. Installation
### Prerequisites
Before installing the IDS, ensure you have the following prerequisites:

- Python 3.8 or higher
- pip (Python package installer)
- Virtualenv (optional but recommended)
- SQLite (default database)
- Internet connection for downloading dependencies

### Steps
#### Clone the Repository:
git clone https://github.com/your-username/ids-project.git
cd ids-project

#### Create a Virtual Environment (optional but recommended):
```python -m venv venv```
```source venv/bin/activate```  # On Windows, use 'venv\Scripts\activate'

#### Install Dependencies:
pip install -r requirements.txt

#### Apply Database Migrations:
python manage.py migrate

#### Create a Superuser:
python manage.py createsuperuser

#### Run the Development Server:
python manage.py runserver

#### Access the Application:
Open your web browser and navigate to http://127.0.0.1:8000/.

## 3. Configuration
Settings
The main configuration file is settings.py. Key settings include:

#### Database Configuration:
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

#### Installed Apps:
Ensure the IDS app is included in the INSTALLED_APPS list:
INSTALLED_APPS = [
    ...
    'ids_app',
]

#### Static Files:
STATIC_URL = '/static/'

Templates:
TEMPLATES = [
    {
        ...
        'DIRS': [BASE_DIR / 'templates'],
        ...
    },
]

#### Environment Variables
You can configure sensitive settings using environment variables. Create a .env file in the project root and add variables like:
SECRET_KEY=your_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1, localhost

## 4. Usage
#### Running the Packet Sniffer
To start capturing network packets and sending data to the IDS:
python sniff.py

#### Accessing the Dashboard
Navigate to http://127.0.0.1:8000/dashboard/ to view the real-time dashboard, including network activity, attack status, and more.

#### Generating Reports
To generate a network activity report, click on the "Generate Report" button on the dashboard.

## 5. API Reference
### Packet Data Endpoint
URL: /api/packet/
Method: POST
Description: Receives packet data.

#### Request Format:
{
    "src_ip": "192.168.1.1",
    "dst_ip": "192.168.1.2",
    "dst_port": 80,
    "protocol": "TCP",
    "length": 1500,
    "is_attack": true,
    "attack_type": "DDoS",
    "timestamp": "2024-06-18T14:43:41.966805"
}

#### Response Format:
{
    "status": "success",
    "message": "Packet saved successfully"
}

### Current Attack Status Endpoint
URL: /api/current-attack-status/
Method: GET
Description: Retrieves the current attack status.

#### Response Format:
{
    "is_under_attack": true,
    "report": "Attack details..."
}
### Historical Data Endpoint
URL: /api/historical-data/
Method: GET
Description: Retrieves historical attack data.

#### Response Format:
{
    "attacks": [
        {
            "name": "DDoS",
            "count": 5,
            "src_ips": ["192.168.1.1", "192.168.1.2"],
            "dst_ips": ["192.168.1.3"],
            "protocols": ["TCP"],
            "mitigation_techniques": ["Increase bandwidth", "Rate limiting"]
        }
    ]
}

## 6. Troubleshooting
### Common Issues
Server Not Starting:

Ensure all dependencies are installed.
Check for any syntax errors in your code.
Review the logs for specific error messages.
Packets Not Being Saved:

Ensure the sniff.py script is running without errors.
Verify that the API endpoint is reachable and responding.
Real-time Updates Not Working:

Check JavaScript console for errors.
Ensure the server is running and accessible.

## 7. Contributing
We welcome contributions to improve the IDS. To contribute:

Fork the repository.
Create a new branch for your feature or bug fix.
Write tests for your changes.
Submit a pull request with a detailed description of your changes.

## 8. License
This IDS project is licensed under the MIT License. See the LICENSE file for more details.