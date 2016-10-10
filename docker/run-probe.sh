#!/bin/bash

PRBDIR=/usr/local/probe

if [ ! -f $PRBDIR/config.ini ] 
then
  [ -z "$PROBE_UUID" -o -z "$PROBE_SECRET" -o -z "$AMQP_USER" -o -z "$AMQP_PASSWD" ] && \
    echo "Required envvars: PROBE_UUID, PROBE_SECRET, AMQP_USER, AMQP_PASSWD." && \
    exit 1
  cp $PRBDIR/config.ini.tmpl $PRBDIR/config.ini
  sed -i $PRBDIR/config.ini \
    -e "s/PROBE_UUID/$PROBE_UUID/" \
    -e "s/PROBE_SECRET/$PROBE_SECRET/" \
    -e "s/AMQP_USER/$AMQP_USER/" \
    -e "s/AMQP_PASSWD/$AMQP_PASSWD/" 
fi

exec /usr/bin/python $PRBDIR/__main__.py -c $PRBDIR/config.ini


