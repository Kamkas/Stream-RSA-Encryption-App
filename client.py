import asyncio
import datetime
import json
import logging
import os
import random

from libs.ciplib import VigenerCipher, StandartEncryptionModes
from libs.rsacrypt import RSACrypt

log = logging.getLogger(__name__)

clients = {}


async def handle_client(host, port):
    log.info("Connecting to %s %d", host, port)
    client_reader, client_writer = await asyncio.open_connection(host,port)
    log.info("Connected to %s %d", host, port)
    data = await client_reader.readline()
    if data is b'' or data is None:
        return
    msg = json.loads(data.decode().rstrip())
    if msg['open_key']:
        rsa = RSACrypt()
        rsa.open_key, rsa.modular = msg['open_key']
        with open('password', 'r') as f:
            pstream = f.read()
            f.close()
        with open('LICENSE.md', 'r') as f:
            tstream = f.read()
            f.close()
        passw_stream = rsa.encrypt((ord(ch) for ch in pstream))
        vc = VigenerCipher()
        stm = StandartEncryptionModes(key=pstream, block_len=2)
        r_init = random.Random()
        r_init.seed(stm.key)
        init_block = (r_init.randint(1, 256) for _ in range(stm.block_len))
        cfb_enc_stream = stm.cfb_decrypt(map(ord, tstream), init_block, vc.encrypt)

        client_writer.write(''.join((json.dumps({'command': 'pass',
                                 'password': list(passw_stream)}), '\n')).encode())
        await client_writer.drain()
        client_writer.write(''.join((json.dumps({'command': 'text',
                                 'text': ''.join((chr(ch) for ch in cfb_enc_stream))}), '\n')).encode())
        await client_writer.drain()
        client_writer.write(''.join((json.dumps({'command': 'decode'}), '\n')).encode())
        await client_writer.drain()
        resp_msg = await client_reader.readline()
        print(json.loads(resp_msg.decode().rstrip()))


def make_connection(host, port):

    task = asyncio.Task(handle_client(host, port))

    clients[task] = (host, port)

    def client_done(task):
        del clients[task]
        log.info("Client Task Finished")
        if len(clients) == 0:
            log.info("clients is empty, stopping loop.")
            loop = asyncio.get_event_loop()
            loop.stop()

    log.info("New Client Task")
    task.add_done_callback(client_done)

if __name__ == '__main__':
    log = logging.getLogger("")
    formatter = logging.Formatter("%(asctime)s %(levelname)s " +
                                  "[%(module)s:%(lineno)d] %(message)s")
    # setup console logging
    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    ch.setFormatter(formatter)
    log.addHandler(ch)

    loop = asyncio.get_event_loop()
    loop.set_debug(1)
    make_connection('localhost', 8888)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    loop.close()
