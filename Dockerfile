FROM python:2.7.14-alpine3.6

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY orgprobe-daemon /orgprobe-daemon
COPY orgprobe /orgprobe

COPY config/docker.config.ini /config.ini

CMD ["python", "/orgprobe-daemon", "-c", "/config.ini"]
