FROM python:3-slim

WORKDIR /app

COPY . .
RUN pip3 install -r ./requirements.txt

ENTRYPOINT ["/app/cloud_enum.py"]
