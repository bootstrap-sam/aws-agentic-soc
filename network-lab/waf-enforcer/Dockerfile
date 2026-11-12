FROM python:3.13-slim
RUN pip install --no-cache-dir boto3==1.40.0
COPY waf.py /app/waf.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/waf.py"]
