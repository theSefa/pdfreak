# Use the official Python image
FROM python:3.9-slim

# Set working directory inside the container
WORKDIR /app

# Copy your code into the container
COPY . /app

# Install system dependencies (optional: depends on peepdf, etc.)
RUN apt-get update && \
    apt-get install -y gcc libxslt-dev libxml2-dev libmagic1 file && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements_py39.txt

# Set default Ollama host for Docker (accessing host machine from inside container)
ENV OLLAMA_HOST=http://host.docker.internal:11434
# Expose the port FastAPI runs on
EXPOSE 8000

# Start the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]