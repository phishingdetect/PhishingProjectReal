FROM python:3.11-slim

WORKDIR /app

COPY requirements-deploy.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements-deploy.txt

COPY phishing_project.zip .
RUN python -m zipfile -e phishing_project.zip /app

EXPOSE 7860

CMD sh -c "cd $(find /app -name app.py -printf '%h\n' | head -n 1) && gunicorn app:app --bind 0.0.0.0:7860 --timeout 300"