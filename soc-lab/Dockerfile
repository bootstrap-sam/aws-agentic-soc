FROM python:3.13-slim
RUN pip install --no-cache-dir boto3==1.40.0
WORKDIR /app
COPY soc ./soc
COPY intel ./intel
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m"]
CMD ["soc.run"]
