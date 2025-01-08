from plutils.log import Logger
from admap.core.nt_security.header import ProtocolHeader
from admap.core.nt_security.dacl import DACL, ACE
from admap.core.nt_security.types import *
import struct

log = Logger(__name__, "#ffaaaa")


"""
Self-relative NTSecurityDescriptor as defined in
https://msdn.microsoft.com/en-us/library/cc230366.aspx
"""
class NTSecurityDescriptor:
    def __init__(self, sd: bytes, dacl: DACL | None, header: ProtocolHeader):
        """
        :param sd: raw binary data
        :param dacl: the dacl of the security descriptor or None if not present
        :param header: the header of the security descriptor
        """
        self.sd = sd
        self.dacl = dacl
        self.header = header

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "SecurityDescriptor":
        """
        Parses the binary data and returns a SecurityDescriptor object
        """
        data = data[offset:]

        revision, sbz1, control, owner, group, sacl_offset, dacl_offset = struct.unpack("<BBHIIII", data[:20])
        header = ProtocolHeader(data=data, header_rows=5, revision=revision, sbz1=sbz1, control=control, owner=owner,
            group=group, sacl_offset=sacl_offset, dacl_offset=dacl_offset)

        # check that sd is self relative
        if not control & 0x8000:
            log.critical("Security descriptor is not self-relative")
            exit(-1)

        dacl = None
        # check that dacl is present
        if control & 0x0004:
            # check that dacl is DI
            if not control & 0x0400:
                log.error("DACL present but doesn't have DI (DACL Auto-Inherited)")
            else:
                dacl = DACL.from_bytes(data, dacl_offset)
        else:
            log.warning("DACL not present in security descriptor")

        return cls(data, dacl, header)

    def __getitem__(self, key):
        return self.sd[key]

    def __len__(self):
        return len(self.sd)

    def __str__(self) -> str:
        return f"[SecurityDescriptor]\n{self.header.table()}\n" + str(self.dacl)
