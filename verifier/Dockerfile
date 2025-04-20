# Base image with Python + pip
FROM python:3.10-slim

# Set workdir and copy app
WORKDIR /app
COPY verifier.py .
COPY templates/ templates/

# Install dependencies
RUN pip install flask cryptography

# Expose port for web UI
EXPOSE 8000

# Run the verifier server
CMD ["python", "verifier.py"]
