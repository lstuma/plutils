from plutils.log import Logger
from admap.core.nt_security.types import *
import struct
import uuid

log = Logger(__name__, "#ffaaaa")


"""
Header for an object, e.g. ACE, ACL, ntSecurityDescriptor etc.
Stores the raw binary data and provides a table representation of the header
as well as access to the attributes of the header and some helper functions
"""
class ProtocolHeader:
    def __init__(self, data: bytes | None = None, header_rows: int | None = None, **kwargs):
        """

        :param data: Raw binary data
        :param header_rows: How many rows to display when rendering header to str
        """
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.data = data
        self.attr = kwargs
        self.header_rows = header_rows

    def table(self) -> str:
        """
        Returns a str representation of the header with specified rows, colored using rich styles

        :return: header in readable string representation
        """
        if not self.header_rows:
            raise ValueError("header_rows not set")
        if not self.data:
            raise ValueError("binary data not set")

        separator = ("+" + "-" * 8) * 4 + "+" + "\n"
        out = separator + ("|[#ffaaaa]01234567[/]|[#ffaaaa]89ABCDEF[/]" * 2) + "|\n"
        for row in range(self.header_rows):
            bins_str = (bin(byte)[2:].rjust(8, "0") for byte in self.data[row*4:row*4+4])
            out += "".join("|" + "".join(["[#88cc88]","[#aaffaa]"][i%2] + digit + "[/]" for i, digit in enumerate(bin_str)) for bin_str in bins_str) + "|\n"
            out += separator
        for key, value in self.attr.items():
            out += f" * [#ffaaaa]{key}[/]: {value}\n"
        return out

    @staticmethod
    def parse_sid(data: bytes, offset: int = 0) -> str:
        """
        Parses a SID at the given offset in the provided data,
        if an invalid SID is being parsed, e.g. invalid revision, the application will crash

        :param offset: the position of the SID in the provided data
        :return: the sid at the given position
        """
        data = data[offset:]

        revision = data[0]
        sub_authority_count = data[1]

        total_sid_length = 8 + 4 * sub_authority_count

        identifier_authority = struct.unpack(">Q", b"\00\00" + data[2:8])[0] & 0xFFFFFFFFFFFF
        sub_authorities = struct.unpack('<' + 'I' * sub_authority_count, data[8:8 + 4 * sub_authority_count])

        identifier_authority_str = str(identifier_authority)
        if identifier_authority >= 2**32:
            identifier_authority_str = '0x' + identifier_authority_str

        sid_str = f'S-{revision}-{identifier_authority_str}'

        for sub_authority in sub_authorities:
            sid_str += f'-{sub_authority}'

        if revision != 1:
            log.critical(f"Invalid SID revision: {revision} at offset {offset}")
            exit(-1)
        return sid_str

    @staticmethod
    def parse_guid(data: bytes, offset: int = 0) -> str:
        """
        Parses the GUID at the given offset in the provided data, see
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40 (guid packet repr)
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/222af2d3-5c00-4899-bc87-ed4c6515e80d (curly braced string repr)

        :param offset: the position of the GUID in the provided data
        :return: the guid at the given position in curly-braced string representation
        """
        guid = uuid.UUID(bytes_le=data[offset:offset+16])
        return f"{{{str(guid)}}}"
