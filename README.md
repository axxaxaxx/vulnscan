# Vulnerability Scanner Web Application

A comprehensive, modular Python web application for vulnerability scanning with professional UI, real-time updates, and compliance checking.

## Features

### Core Functionality
- **Port Scanning**: Nmap-based port scanning with service detection
- **Vulnerability Detection**: CVE database lookups and exploit identification
- **OSINT Collection**: Web scraping for threat intelligence
- **Compliance Checking**: NIST Cybersecurity Framework compliance mapping
- **Real-time Updates**: WebSocket-based live scan progress
- **Background Processing**: Celery task queue for long-running scans
- **PDF Reporting**: Professional report generation with WeasyPrint/ReportLab

### Web Interface
- **Modern UI**: Clean, responsive design with Tailwind CSS
- **Dashboard**: Real-time statistics and monitoring
- **Scan Management**: Create, start, stop, and monitor scans
- **Customer Management**: Organize scans by customer/client
- **Report Editor**: Review and modify scan results before export
- **Monitoring**: System health and performance metrics

### Security Features
- **NIST Compliance**: Maps vulnerabilities to NIST controls
- **Risk Scoring**: Automated risk assessment and prioritization
- **Exploit Database**: Searchsploit integration for exploit discovery
- **CVE Lookups**: Comprehensive vulnerability information retrieval

## Installation

### Quick Setup (Recommended)

For first-time installation, use the automated setup script:

```bash
# Clone the repository
git clone https://github.com/axxaxaxx/vulnerabilityScannerWebApp.git
cd vulnerabilityScannerWebApp

# Make setup script executable and run it
chmod +x setup.sh
./setup.sh
```

The setup script will automatically:
- Check system requirements (Python 3.8+, Redis, Nmap)
- Create a Python virtual environment
- Install all dependencies
- Set up environment variables
- Initialize the database
- Install Searchsploit (optional)
- Run tests to verify installation
- Create startup scripts

After setup completes, start the application:
```bash
./start.sh
```

### Manual Setup

If you prefer manual installation:

#### Prerequisites
- Python 3.8+
- Redis server
- Nmap
- Searchsploit (optional)

#### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/axxaxaxx/vulnerabilityScannerWebApp.git
   cd vulnerabilityScannerWebApp
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

6. **Start Redis server**
   ```bash
   redis-server
   ```

7. **Start Celery worker** (in separate terminal)
   ```bash
   celery -A app.celery worker --loglevel=info
   ```

8. **Start the application**
   ```bash
   python app.py
   ```

The application will be available at `http://localhost:5000`.

### Verify Installation

Run the test script to verify everything is working:
```bash
python test_installation.py
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_APP` | Flask application entry point | `app.py` |
| `FLASK_ENV` | Flask environment | `development` |
| `SECRET_KEY` | Flask secret key | `dev-secret-key` |
| `DATABASE_URL` | Database connection string | `sqlite:///vuln_scanner.db` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend | `redis://localhost:6379/0` |

### Nmap Configuration

The application uses python-nmap for port scanning. Configure scan options in the scan creation form or via API:

```json
{
  "ports": "1-1000",
  "arguments": "-sS -sV -O --script vuln"
}
```

### Searchsploit Setup

For exploit database lookups, ensure searchsploit is installed and accessible:

```bash
# Install ExploitDB
git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
```

## Usage

### Web Interface

1. **Dashboard**: View system statistics and recent activity
2. **Create Scan**: Add new vulnerability scans for targets
3. **Monitor Scans**: Real-time progress tracking
4. **View Results**: Detailed vulnerability and compliance reports
5. **Generate Reports**: Export PDF reports for stakeholders

### API Endpoints

#### Customers
- `GET /api/customers` - List all customers
- `POST /api/customers` - Create new customer
- `GET /api/customers/<id>` - Get customer details
- `PUT /api/customers/<id>` - Update customer
- `DELETE /api/customers/<id>` - Delete customer

#### Scans
- `GET /api/scans` - List scans with filtering
- `POST /scan/create` - Create new scan
- `POST /scan/<id>/start` - Start scan
- `POST /scan/<id>/stop` - Stop scan
- `GET /scan/<id>/status` - Get scan status
- `GET /api/scans/<id>` - Get scan details

#### Reports
- `POST /report/<id>/generate` - Generate PDF report
- `GET /report/<id>/preview` - Preview report data
- `POST /report/<id>/export` - Export report in various formats

#### Monitoring
- `GET /monitor/dashboard` - Get dashboard data
- `GET /monitor/system` - Get system information
- `GET /monitor/logs` - Get system logs
- `GET /monitor/health` - Health check

### WebSocket Events

The application uses Socket.IO for real-time updates:

- `scan_update` - Scan progress updates
- `scan_complete` - Scan completion notifications
- `scan_progress` - Detailed progress information

## Architecture

### Backend Components

- **Flask Application**: Main web framework
- **SQLAlchemy**: Database ORM
- **Celery**: Background task processing
- **Redis**: Message broker and caching
- **Socket.IO**: Real-time communication

### Scanning Modules

- **NmapScanner**: Port scanning and service detection
- **SearchsploitScanner**: Exploit database lookups
- **CVELookup**: CVE information retrieval
- **OSINTScanner**: Open source intelligence collection
- **ComplianceChecker**: NIST framework compliance

### Frontend

- **Tailwind CSS**: Utility-first CSS framework
- **Chart.js**: Data visualization
- **Socket.IO Client**: Real-time updates
- **Vanilla JavaScript**: Interactive functionality

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_models.py
```

### Code Structure

```
vuln_scanner_webapp/
├── app/
│   ├── models.py              # Database models
│   ├── modules/               # Scanning modules
│   │   ├── nmap_scanner.py
│   │   ├── searchsploit_scanner.py
│   │   ├── cve_lookup.py
│   │   ├── osint_scanner.py
│   │   ├── compliance_checker.py
│   │   ├── pdf_generator.py
│   │   └── logger.py
│   ├── routes/                # API routes
│   │   ├── main.py
│   │   ├── api.py
│   │   ├── scan.py
│   │   ├── report.py
│   │   └── monitor.py
│   ├── tasks/                 # Celery tasks
│   │   └── scan_tasks.py
│   └── templates/             # HTML templates
│       ├── base.html
│       ├── index.html
│       ├── scans.html
│       └── scan_detail.html
├── tests/                     # Test files
├── requirements.txt           # Python dependencies
├── app.py                    # Application entry point
└── README.md                 # This file
```

## Security Considerations

- **Input Validation**: All user inputs are validated and sanitized
- **SQL Injection**: SQLAlchemy ORM prevents SQL injection
- **XSS Protection**: Template escaping prevents cross-site scripting
- **CSRF Protection**: Flask-WTF CSRF tokens (recommended)
- **Access Control**: Implement authentication and authorization
- **Secure Headers**: Add security headers for production

## Production Deployment

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
```

### Environment Setup

1. Use production database (PostgreSQL recommended)
2. Configure Redis for production
3. Set up proper logging
4. Use environment variables for secrets
5. Enable HTTPS with SSL certificates
6. Configure firewall rules
7. Set up monitoring and alerting

### Scaling

- **Horizontal Scaling**: Multiple application instances
- **Load Balancing**: Nginx or HAProxy
- **Database Scaling**: Read replicas, connection pooling
- **Redis Clustering**: For high availability
- **Celery Scaling**: Multiple worker processes

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the test files for usage examples

## Changelog

### Version 1.0.0
- Initial release
- Core vulnerability scanning functionality
- Web interface with real-time updates
- NIST compliance checking
- PDF report generation
- Background task processing
- Comprehensive test suite
