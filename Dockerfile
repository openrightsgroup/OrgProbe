
FROM ubuntu:16.04

RUN apt-get update 
RUN apt-get -y install python-requests \
    python-pyasn1 \
    #python-ndg-httpsclient \
    python-amqplib \
    python-redis
RUN apt-get clean

RUN mkdir /usr/local/probe

COPY *.py /usr/local/probe/
COPY docker/run-probe.sh /usr/local/probe/run-probe.sh
COPY docker/config.ini.tmpl /usr/local/probe/config.ini.tmpl
COPY docker/configure.py /usr/local/probe/configure.py

RUN chmod a+x /usr/local/probe/run-probe.sh

CMD /usr/local/probe/run-probe.sh
