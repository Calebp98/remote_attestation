FROM python:3.10-slim

WORKDIR /app

# Copy application files
COPY prover.py prover_core.py ./
COPY start.sh config.json ./app_files/

# Install required libraries
RUN pip install requests cryptography

# Run the prover
CMD ["python", "prover.py"]
