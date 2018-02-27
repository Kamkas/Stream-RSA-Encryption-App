import asyncio
import datetime
import json
import logging
import os
import random

from libs.ciplib import VigenerCipher, StandartEncryptionModes
from libs.rsacrypt import RSACrypt


class RSAStreamCipherServer:
    def __init__(self):
        pass


log = logging.getLogger(__name__)

clients = {}


async def decode(tbuffer_stream, pbuffer_stream, peername, rsa):

    passw_stream = rsa.decrypt(pbuffer_stream)
    vc = VigenerCipher()
    stm = StandartEncryptionModes(key=passw_stream, block_len=2)
    r_init = random.Random()
    r_init.seed(stm.key)
    init_block = (r_init.randint(1, 256) for _ in range(stm.block_len))
    cfb_dec_stream = stm.cfb_decrypt(tbuffer_stream, init_block, vc.encrypt)

    log.info('Starting decryption from {}'.format(peername))

    with open(os.path.join(os.getcwd(),
                           'msgs', 'pass_{}'.format(str(datetime.datetime.now().isoformat()))), 'w') as f:
        for item in passw_stream:
            f.write(chr(item))
        f.close()
    with open(os.path.join(os.getcwd(),
                           'msgs', 'text_{}'.format(str(datetime.datetime.now().isoformat()))), 'w') as f:
        for item in cfb_dec_stream:
            f.write(chr(item))
        f.close()
    log.info('Stop decryption from {}'.format(peername))


async def handle_client(client_reader, client_writer):
    rsa = RSACrypt()
    rsa.read_keys(open_key_filename=os.path.join(os.getcwd(), 'open_key.txt'),
                  private_key_filename=os.path.join(os.getcwd(), 'close_key.txt'))
    key_msg = ''.join((json.dumps({'open_key': (rsa.open_key, rsa.modular)}), '\n')).encode()
    client_writer.write(key_msg)
    await client_writer.drain()
    log.info("Send open key to {}".format(client_writer.get_extra_info('peername')))
    pbuffer, tbuffer = [], []
    while True:
        data = await client_reader.readline()
        if not data:
            break
        log.debug('Received {0} bytes from {1}'.format(data.__sizeof__(), client_writer.get_extra_info('peername')))
        msg = json.loads(data.decode().rstrip())
        if msg['command'] == 'pass':
            pbuffer.append(msg['password'])
            log.debug('Pass: {0} bytes; {1}'.format(len(msg['password']), client_writer.get_extra_info('peername')))
        elif msg['command'] == 'text':
            tbuffer.append(msg['text'])
            log.debug('Text: {0} bytes; {1}'.format(len(msg['text']), client_writer.get_extra_info('peername')))
        elif msg['command'] == 'decode':
            if pbuffer is not [] and tbuffer is not []:
                t_stream = map(ord, (i for block in tbuffer for i in block))
                p_stream = (i for block in pbuffer for i in block)
                await decode(t_stream, p_stream, client_writer.get_extra_info('peername'), rsa)
                client_writer.write(''.join((json.dumps({'message': 'OK'}), '\n')).encode())
                await client_writer.drain()
                break


def accept_client(client_reader, client_writer):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info("End Connection")

    log.info("New Connection")
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
    f = asyncio.start_server(accept_client, host='localhost', port=8888, loop=loop)
    loop.run_until_complete(f)
    loop.run_forever()
    loop.close()