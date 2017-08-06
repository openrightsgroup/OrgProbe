#!/bin/bash

PRBDIR=/usr/local/probe
CONFIG=$PRBDIR/config.ini

if [ ! -f $CONFIG ] 
then
  python $PRBDIR/configure.py -o $CONFIG
fi

exec /usr/local/bin/orgprobe.py -c $PRBDIR/config.ini 


