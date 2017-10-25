FROM python:2.7.14-alpine3.6

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY orgprobe /orgprobe
COPY OrgProbe /OrgProbe

COPY config/docker.config.ini /config.ini

CMD ["python", "/orgprobe", "-c", "/config.ini"]
