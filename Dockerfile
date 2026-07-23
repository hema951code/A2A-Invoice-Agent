FROM python:3.11-slim

WORKDIR /app

COPY requirements-a2a.txt .
RUN pip install --no-cache-dir -r requirements-a2a.txt

COPY a2a_app.py .

RUN mkdir -p /app/data

ENV PORT=10000
EXPOSE 10000

CMD ["python3", "a2a_app.py"]
