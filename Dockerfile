FROM python:2.7

ARG CONFIGFILE=config/docker.config.ini

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY orgprobe-daemon /orgprobe-daemon
COPY orgprobe /orgprobe

COPY $CONFIGFILE /config.ini

WORKDIR /
CMD ["python", "orgprobe-daemon", "-c", "config.ini"]
