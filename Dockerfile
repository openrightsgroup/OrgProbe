
FROM debian:9

RUN apt-get update && apt-get -y install python-requests \
    python-pyasn1 \
    #python-ndg-httpsclient \
    python-pika \
    python-redis
RUN apt-get clean

RUN mkdir /usr/local/probe

RUN mkdir -p /usr/local/src/orgprobe
COPY setup.py /usr/local/src/orgprobe/
COPY orgprobe /usr/local/src/orgprobe/
COPY OrgProbe /usr/local/src/orgprobe/OrgProbe/

RUN cd /usr/local/src/orgprobe && /usr/bin/python setup.py install
COPY docker/run-probe.sh /usr/local/probe/run-probe.sh
COPY docker/config.ini.tmpl /usr/local/probe/config.ini.tmpl
COPY docker/configure.py /usr/local/probe/configure.py

RUN chmod a+x /usr/local/probe/run-probe.sh

CMD /usr/local/probe/run-probe.sh
