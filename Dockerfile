FROM python:3.12-slim

WORKDIR /app
# Automatically remediate fixable pip vulnerabilities
RUN python -m pip install --no-cache-dir --upgrade pip


COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5000

CMD ["python", "app.py"]

RUN apt-get update &&     apt-get upgrade -y &&     rm -rf /var/lib/apt/lists/*
