FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    postgresql-client \
    redis-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install ExploitDB for searchsploit
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs reports

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONPATH=/app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/monitor/health || exit 1

# Run the application
CMD ["python", "run.py"]
