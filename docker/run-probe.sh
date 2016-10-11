#!/bin/bash

PRBDIR=/usr/local/probe
CONFIG=$PRBDIR/config.ini

if [ ! -f $CONFIG ] 
then
  [ -z "$PROBE_UUID" -o -z "$PROBE_SECRET" -o -z "$AMQP_USER" -o -z "$AMQP_PASSWD" ] && \
    echo "Required envvars: PROBE_UUID, PROBE_SECRET, AMQP_USER, AMQP_PASSWD." && \
    exit 1

  # use API_HOST if defined
  API_HOST=${API_HOST:-api.blocked.org.uk}

  # create config file from template
  cp $PRBDIR/config.ini.tmpl $CONFIG
  sed -i $CONFIG \
    -e "s/API_HOST/$API_HOST/" \
    -e "s/PROBE_UUID/$PROBE_UUID/" \
    -e "s/PROBE_SECRET/$PROBE_SECRET/" \
    -e "s/AMQP_USER/$AMQP_USER/" \
    -e "s/AMQP_PASSWD/$AMQP_PASSWD/" 

  if [ ! -z "$REDIS" ]
  then
    PROBE_LIMIT=${PROBE_LIMIT:-200000000}
    echo "limit = $PROBE_LIMIT" >> $CONFIG
    echo "" >> $CONFIG
    echo "[accounting]" >> $CONFIG
    echo "redis_server = $REDIS" >> $CONFIG
  fi
fi

exec /usr/bin/python $PRBDIR/__main__.py -c $PRBDIR/config.ini


