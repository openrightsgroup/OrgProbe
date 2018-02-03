import json
import logging
import pika


class AMQPQueue(object):
    SIG_KEYS = ["probe_uuid", "url", "status", "date", "config"]

    def __init__(self, opts, network, queue_name, signer, test_method, lifetime=None):
        creds = pika.PlainCredentials(
            opts['userid'],
            opts['passwd'],
        )
        self.params = pika.ConnectionParameters(
            host=opts['host'],
            credentials=creds,
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
        self.test_method = test_method

        self.conn = None
        self.ch = None
        self.consumer_tag = None

    def start(self):
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
        data = json.loads(msg.decode('utf8'))
        logging.debug("Got data: %s", data)
        self.ch.basic_ack(method.delivery_tag)
        self.test_method(data)
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

    def send(self, report, urlhash=None):
        """Sends a report back to the server"""

        report['date'] = self.signer.timestamp()
        report['signature'] = self.signer.get_signature(report, self.SIG_KEYS)

        msg = json.dumps(report)
        key = 'results.' + self.network + '.' + \
              urlhash if urlhash is not None else ''
        logging.debug("Sending result with key: %s", key)
        self.ch.basic_publish('org.blocked', key, msg)
