from ctypes import *
from gnutls.library import libgnutls
from gnutls.errors import GNUTLSError
from gnutls.library.types import *
from gnutls.library.errors import ErrorMessage
from gnutls.connection import Session, ClientSession, ServerSession

class GNUTLSRange(Structure):
    _fields_ = [('low', size_t), ('high', size_t)]

gnutls_record_can_use_length_hiding = libgnutls.gnutls_record_can_use_length_hiding
gnutls_record_can_use_length_hiding.argtypes = [gnutls_session_t]
gnutls_record_can_use_length_hiding.restype = c_int

gnutls_record_send_range = libgnutls.gnutls_record_send_range
gnutls_record_send_range.argtypes = [gnutls_session_t, c_void_p, size_t, POINTER(GNUTLSRange)]
gnutls_record_send_range.restype = ssize_t

class LengthHidingSession(Session):
    def send_range(self, data, padding_range):
        range_ = GNUTLSRange()
        data = str(data)
        size = len(data)
        while size > 0:
            range_.low = size + padding_range[0]
            range_.high = size + padding_range[1]
            sent = gnutls_record_send_range(self._c_object, data[-size:], size, byref(range_))
            if sent < 0:
                raise GNUTLSError(ErrorMessage(sent))
            size -= sent

    def can_use_length_hiding(self):
        return gnutls_record_can_use_length_hiding(self._c_object)

class LengthHidingClientSession(ClientSession, LengthHidingSession):
    pass

class LengthHidingServerSession(ServerSession, LengthHidingSession):
    pass
