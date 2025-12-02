# -------------------------
# E2E OIDC Dummy Provider
# -------------------------

FROM python:3.11-slim

# Set workdir
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Expose Flask port
EXPOSE 5000

# Run the app
CMD ["python", "main.py"]
