OrgProbe
========

A python probe using the OpenRightsGroup/BlockingMiddleware API.  Also supports AMQP.

This is work in progress, although the HTTP mode has been pretty well tested and has submitted over 8,000 results.

Requires the following libraries:

requests
amqplib (when using AMQP mode).

The rest is standard library stuff.

Still todo:

* setup.py

To run:

cd /path/above/checkout

python -m OrgProbe -c /path/to/config

An example config file is included.  You'll need to use the new-user signup and probe registration calls in the API to get credentials.  The registration routine built into OrgProbe is alpha-quality at best.



