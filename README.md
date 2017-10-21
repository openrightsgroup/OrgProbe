OrgProbe
========

A python probe using the [OpenRightsGroup](https://www.openrightsgroup.org/) 
[BlockingMiddleware API](https://github.com/openrightsgroup/Blocking-Middleware).
Also supports [AMQP](https://en.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol).

This is work in progress, although the HTTP mode has been pretty well tested 
and has submitted over 8,000 results.

## Setup

Requires python 2.7.

    pip install -r requirements.txt

## Run

    python orgprobe -c path/to/config

An example config file is included.  You'll need to use the new-user signup and
 probe registration calls in the API to get credentials.  The registration 
 routine built into OrgProbe is alpha-quality at best.

If you're running the Blocking-Middleware Vagrant VM, you can start OrgProbe 
with the `config.vagrant.ini` config file, which will start a nice fast 
HTTP-mode poll against the FakeISP set up in the VM database.

## Unit Tests

To run the unit tests against all currently supported python versions, 

    pip install tox
    tox

## Probe behaviour

On Startup:

* Retrieve API config from Middleware, unless overridden locally.
* Determine own IP address via call to Middleware, and hence  determine likely.
  ISP.  If this can't be determined then it should be overridden manually in 
  the configuration.
* Run self test using a list of known available and known blocked sites for 
  that ISP, to check connectivity and that filters are enabled on this 
  line.
* Open AMQP queue to listen for incoming requests.

For each incoming request in the AMQP queue:

* Attempt to retrieve the URLs in the request.
* Detect blocking type.
* Report result back to the queue.

## TODO 

* Setup.py