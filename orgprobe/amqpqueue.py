import json
import logging
import pika


class AMQPQueue(object):
    def __init__(self, opts, network, queue_name, signer, lifetime=None):
        creds = pika.PlainCredentials(
            opts['userid'],
            opts['passwd'],
        )
        self.params = pika.ConnectionParameters(
            host=opts['host'],
            credentials=creds,
            virtual_host=opts.get('vhost', '/'),
            port=int(opts.get('port', 5672)),
            heartbeat_interval=15,
        )
        self.network = network
        logging.debug("Opening AMQP connection")
        self.signer = signer
        self.queue_name = 'url.' + network + '.' + queue_name
        logging.info("Listening on queue: %s", self.queue_name)
        self.lifetime = lifetime
        self.alive = True
        self.count = 0
        self.prefetch = int(opts['prefetch']) if 'prefetch' in opts else None

        self.conn = None
        self.ch = None
        self.consumer_tag = None

        self.callback = None

    def start(self, callback):
        self.callback = callback
        self.conn = pika.SelectConnection(
            self.params,
            on_open_callback=self.on_open,
            stop_ioloop_on_close=True
        )
        self.conn.ioloop.start()

    def on_open(self, conn):
        self.conn.channel(self.on_channel_open)

    def on_channel_open(self, ch):
        self.ch = ch
        if self.prefetch:
            logging.debug("Setting QOS prefetch to %s", self.prefetch)
            self.ch.basic_qos(None, 0, int(self.prefetch), False)
        self.consumer_tag = self.ch.basic_consume(self.decode_msg, queue=self.queue_name)

    def decode_msg(self, channel, method, props, msg):
        # this is a wrapper callback that decodes the json data
        # before passing it to the probe's real callback
        self.ch.basic_ack(method.delivery_tag)
        logging.info(msg)
        data = json.loads(msg.decode('utf8'))
        logging.debug("Got data: %s", data)

        self.callback(data)
        self.count += 1
        logging.debug("Count: %s, Lifetime: %s", self.count, self.lifetime)
        if self.lifetime is not None and self.count >= self.lifetime:
            logging.info("Cancelling subscription due to lifetime expiry")
            self.ch.basic_cancel(self.on_cancel, self.consumer_tag)

    def on_cancel(self, *args):
        self.ch.close()
        self.conn.close()

    def close(self):
        self.conn.close()

    def send_report(self, report, urlhash=None):
        routing_key = 'results.' + self.network + '.' + \
            urlhash if urlhash is not None else ''
        report['date'] = self.signer.timestamp()

        report['signature'] = self.signer.get_signature(
            args=report,
            keys=["probe_uuid", "url", "status", "date", "config"])

        self.send(routing_key, report)

    def send(self, routing_key, report):
        """Sends a report back to the server"""

        msg = json.dumps(report)

        logging.debug("Sending report with routing_key: %s", routing_key)
        self.ch.basic_publish('org.blocked', routing_key, msg)
