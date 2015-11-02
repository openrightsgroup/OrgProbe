import threading
import time
import datetime
import json
import amqplib.client_0_8 as amqp
import logging


class Heartbeat(object):
    def __init__(self, amqpconn, interval, uuid):
        self.amqpconn = amqpconn
        self.ch = amqpconn.channel()
        self.uuid = uuid
        self.interval = interval
        self.alive = True

    def get_message(self):
        data = {
            'probe_uuid': self.uuid,
            'date': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
        return amqp.Message(json.dumps(data))

    def run(self):
        key = 'probe.heartbeat.' + self.uuid
        self.alive = True
        while self.alive:
            logging.debug("Sending heartbeat")
            try:
                self.ch.basic_publish(self.get_message(), 'org.blocked', key)
            except Exception, v:
                logging.error("Heartbeat: %s: %s", repr(v), str(v))
            logging.debug("Sleeping")
            for i in range(5):
                if not self.alive:
                    logging.debug("Interrupted")
                    break
                time.sleep(self.interval / 5.0)

    def start_thread(self):
        t = threading.Thread(target=self.run)
        t.start()

    def stop_thread(self):
        logging.debug("Stopping...")
        self.alive = False
