FROM python:3.11-slim

WORKDIR /app

COPY requirements-deploy.txt .

RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements-deploy.txt

COPY . .

WORKDIR /app/Phishing-Email-Detection-Using-DL

EXPOSE 7860

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7860", "--timeout", "300"]