import asyncio
import base64
import gzip
import io
import logging
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from pixelazertl._security import MAX_PACKET_SIZE
from pixelazertl._web import PublicResolver, validate_url, download
from pixelazertl.client.uploads import _is_session_file, _session_content_detected, _is_sensitive_name
from pixelazertl.errors import SecurityError
from pixelazertl.extensions import BinaryReader
from pixelazertl.network.connection.tcpfull import FullPacketCodec
from pixelazertl.network.connection.tcpabridged import AbridgedPacketCodec
from pixelazertl.network.connection.tcpintermediate import IntermediatePacketCodec
from pixelazertl.network.authenticator import do_authentication
from pixelazertl.sessions import SQLiteSession
from pixelazertl.tl.core.gzippacked import GzipPacked
from pixelazertl.tl.core import MessageContainer, RpcResult


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    def test_container_rpc_bodies_do_not_include_following_messages(self):
        body = struct.pack('<IqI', RpcResult.CONSTRUCTOR_ID, 1, 0x997275b5)
        message = struct.pack('<qii', 1, 1, len(body)) + body
        result = MessageContainer.from_reader(BinaryReader(struct.pack('<i', 2) + message * 2))
        self.assertEqual([m.obj.body for m in result.messages], [body[-4:]] * 2)

    def test_container_rejects_invalid_counts_lengths_and_nesting(self):
        payload = struct.pack('<I', 0x997275b5)
        message = struct.pack('<qii', 1, 1, 4) + payload
        for count in (-1, 1025):
            with self.subTest(count=count), self.assertRaises(BufferError):
                MessageContainer.from_reader(BinaryReader(struct.pack('<i', count) + message * max(count, 0)))
        for length in (-4, 0, 3, 8):
            with self.subTest(length=length), self.assertRaises(BufferError):
                MessageContainer.from_reader(BinaryReader(struct.pack('<iqii', 1, 1, 1, length) + payload))
        nested = struct.pack('<Ii', MessageContainer.CONSTRUCTOR_ID, 0)
        with self.assertRaises(BufferError):
            MessageContainer.from_reader(BinaryReader(struct.pack('<iqii', 1, 1, 1, len(nested)) + nested))
        self.assertEqual(MessageContainer.from_reader(BinaryReader(struct.pack('<i', 0))).messages, [])

    def test_container_compressed_messages_share_an_expansion_limit(self):
        for body in (bytes(GzipPacked(b'x' * 1024)), struct.pack('<Iq', RpcResult.CONSTRUCTOR_ID, 1) + bytes(GzipPacked(b'x' * 1024))):
            message = struct.pack('<qii', 1, 1, len(body)) + body
            with patch('pixelazertl.tl.core.messagecontainer.MAX_UNCOMPRESSED_SIZE', 2048):
                self.assertEqual(len(MessageContainer.from_reader(BinaryReader(struct.pack('<i', 2) + message * 2)).messages), 2)
                with self.assertRaises(BufferError):
                    MessageContainer.from_reader(BinaryReader(struct.pack('<i', 3) + message * 3))

    def test_gzip_round_trip_and_limit(self):
        data = b'hello' * 20
        self.assertEqual(GzipPacked._decompress(gzip.compress(data)), data)
        with patch('pixelazertl.tl.core.gzippacked.MAX_UNCOMPRESSED_SIZE', 32):
            with self.assertRaises(ValueError):
                GzipPacked._decompress(gzip.compress(b'x' * 33))
            self.assertEqual(GzipPacked._decompress(gzip.compress(b'x' * 32)), b'x' * 32)

    async def test_reject_packet_lengths_before_body_read(self):
        cases = [
            (FullPacketCodec, struct.pack('<ii', 9, 0)),
            (FullPacketCodec, struct.pack('<ii', MAX_PACKET_SIZE + 1, 0)),
            (AbridgedPacketCodec, b'\x7f' + ((MAX_PACKET_SIZE // 4) + 1).to_bytes(3,'little')),
            (IntermediatePacketCodec, struct.pack('<i', -1)),
            (IntermediatePacketCodec, struct.pack('<i', MAX_PACKET_SIZE + 1)),
        ]
        for codec, header in cases:
            reader = asyncio.StreamReader(); reader.feed_data(header); reader.feed_eof()
            with self.subTest(codec=codec.__name__,header=header):
                with self.assertRaises(Exception) as caught:
                    await codec(None).read_packet(reader)
                self.assertNotIsInstance(caught.exception, asyncio.IncompleteReadError)

    async def test_regular_packet_round_trip(self):
        for codec in (FullPacketCodec, AbridgedPacketCodec, IntermediatePacketCodec):
            instance=codec(None); reader=asyncio.StreamReader(); reader.feed_data(instance.encode_packet(b'1234'));reader.feed_eof()
            self.assertEqual(await instance.read_packet(reader),b'1234')

    def test_private_urls_and_credentials_rejected(self):
        for url in ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data', 'http://10.0.0.1', 'http://[::1]', 'http://[::ffff:127.0.0.1]', 'file:///etc/passwd', 'https://user:secret@example.com']:
            with self.subTest(url=url), self.assertRaises(ValueError): validate_url(url)
        validate_url('https://example.com/file')
        validate_url('https://8.8.8.8/file')

    async def test_dns_rebinding_and_mixed_answers_rejected(self):
        resolver=PublicResolver()
        try:
            for answers in [[{'host':'127.0.0.1'}],[{'host':'8.8.8.8'},{'host':'10.0.0.1'}]]:
                with patch('aiohttp.resolver.DefaultResolver.resolve',new=AsyncMock(return_value=answers)):
                    with self.assertRaises(ValueError):await resolver.resolve('example.com')
        finally:await resolver.close()

    async def test_private_download_not_connected(self):
        with patch('aiohttp.ClientSession.get') as request:
            with self.assertRaises(ValueError):await download('http://127.0.0.1',io.BytesIO())
            request.assert_not_called()

    def test_sessions_private_even_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=os.umask(0)
            try:session=SQLiteSession(str(Path(tmp)/'account'));session.save();session.close()
            finally:os.umask(old)
            self.assertEqual((Path(tmp)/'account.session').stat().st_mode & 0o777,0o600)
            (Path(tmp)/'link.session').symlink_to(Path(tmp)/'account.session')
            with self.assertRaises(OSError):SQLiteSession(str(Path(tmp)/'link'))

    async def test_renamed_session_inspected_without_aiofiles(self):
        data=b'SQLite format 3\x00create table sessions auth_key blob'
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'innocent.bin';p.write_bytes(data)
            self.assertTrue(await _is_session_file(p))
        self.assertTrue(_session_content_detected(base64.b64encode(data)))
        self.assertTrue(_is_sensitive_name('ACCOUNT.SESSION'))
        self.assertFalse(await _is_session_file(b'ordinary image contents'))

    def test_invalid_tl_vectors_and_byte_prefix(self):
        for count in [-1,100000]:
            reader=BinaryReader(struct.pack('<Ii',0x1cb5c415,count))
            with self.assertRaises(BufferError):reader.tgread_vector()
        with self.assertRaises(BufferError):BinaryReader(b'\xff').tgread_bytes()

    async def test_authentication_type_check_active_under_optimization(self):
        sender=AsyncMock();sender.send.return_value=object()
        with self.assertRaises(SecurityError):await do_authentication(sender)




class EncryptedMessageTests(unittest.TestCase):
    def test_message_length_and_padding_are_authenticated_and_validated(self):
        import time
        from collections import defaultdict
        from hashlib import sha256
        from pixelazertl.crypto import AES, AuthKey
        from pixelazertl.network.mtprotostate import MTProtoState
        from pixelazertl.tl.types import Pong
        key = AuthKey(os.urandom(256))
        state = MTProtoState(key, loggers=defaultdict(lambda: logging.getLogger('test')))
        obj = bytes(Pong(msg_id=1, ping_id=42))
        def encrypt(claimed_size):
            clear=struct.pack('<qqqii',0,state.id,(int(time.time()) << 32) | 1,1,claimed_size)+obj
            clear+=os.urandom((-len(clear)) % 16)
            msg_key=sha256(key.key[96:128]+clear).digest()[8:24]
            aes_key,aes_iv=state._calc_key(key.key,msg_key,False)
            return struct.pack('<Q',key.key_id)+msg_key+AES.encrypt_ige(clear,aes_key,aes_iv)
        for claimed in [-1,1,len(obj)+12]:
            with self.subTest(claimed=claimed),self.assertRaises(SecurityError):
                state.decrypt_message_data(encrypt(claimed))
        result=state.decrypt_message_data(encrypt(len(obj)))
        self.assertEqual(result.obj.ping_id,42)

if __name__ == '__main__':unittest.main()
