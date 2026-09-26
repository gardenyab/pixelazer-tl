from .tlmessage import TLMessage
from ..tlobject import TLObject
from ..._security import MAX_UNCOMPRESSED_SIZE
from .gzippacked import GzipPacked
from .rpcresult import RpcResult


class MessageContainer(TLObject):
    CONSTRUCTOR_ID = 0x73F1F8DC

    # Maximum size in bytes for the inner payload of the container.
    # Telegram will close the connection if the payload is bigger.
    # The overhead of the container itself is subtracted.
    MAXIMUM_SIZE = 1044456 - 8

    # Maximum amount of messages that can't be sent inside a single
    # container, inclusive. Beyond this limit Telegram will respond
    # with BAD_MESSAGE 64 (invalid container).
    #
    # This limit is not 100% accurate and may in some cases be higher.
    # However, sending up to 100 requests at once in a single container
    # is a reasonable conservative value, since it could also depend on
    # other factors like size per request, but we cannot know this.
    MAXIMUM_LENGTH = 100

    def __init__(self, messages):
        self.messages = messages

    def to_dict(self):
        return {
            "_": "MessageContainer",
            "messages": (
                []
                if self.messages is None
                else [None if x is None else x.to_dict() for x in self.messages]
            ),
        }

    @classmethod
    def from_reader(cls, reader):
        from ...extensions import BinaryReader

        count = reader.read_int()
        # Each inner message has a 16-byte header and at least a constructor.
        if not 0 <= count <= min(1024, (len(reader.get_bytes()) - reader.tell_position()) // 20):
            raise BufferError("Invalid MTProto container count")
        messages = []
        expanded_size = 0
        for _ in range(count):
            msg_id = reader.read_long()
            seq_no = reader.read_int()
            length = reader.read_int()
            remaining = len(reader.get_bytes()) - reader.tell_position()
            if length < 4 or length % 4 or length > remaining:
                raise BufferError("Invalid MTProto inner message length")
            # RPC results consume the remainder of their reader. Isolate each
            # body so they cannot copy or parse subsequent messages as payload.
            with BinaryReader(reader.read(length)) as inner:
                if inner.read_int(signed=False) == cls.CONSTRUCTOR_ID:
                    raise BufferError("Nested MTProto containers are not allowed")
                inner.seek(-4)
                obj = inner.tgread_object()
                if inner.tell_position() != length:
                    raise BufferError("MTProto inner message length mismatch")
            expanded = (
                len(obj.data) if isinstance(obj, GzipPacked)
                else len(obj.body or b"") if isinstance(obj, RpcResult)
                else length
            )
            expanded_size += max(length, expanded)
            if expanded_size > MAX_UNCOMPRESSED_SIZE:
                raise BufferError("Expanded MTProto container exceeds size limit")
            messages.append(TLMessage(msg_id, seq_no, obj))
        return MessageContainer(messages)
