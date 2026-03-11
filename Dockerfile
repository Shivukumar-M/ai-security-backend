# backend/Dockerfile
# Use a Python base image for performance
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_HOME /app
WORKDIR $APP_HOME

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY ./app $APP_HOME/app

# Create necessary directories for models and logs (even if models are downloaded)
RUN mkdir -p $APP_HOME/app/media/generated_logs \
    && mkdir -p $APP_HOME/app/media/reports \
    && mkdir -p $APP_HOME/app/rag_engine/vectorstore

# Command to run the application (Gunicorn + Uvicorn for production)
# Use Uvicorn directly for Render simplicity, binding to 0.0.0.0 for container
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]