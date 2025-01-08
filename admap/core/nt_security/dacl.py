from plutils.log import Logger
from admap.core.nt_security.header import ProtocolHeader
from admap.core.nt_security.types import *
import struct

log = Logger(__name__, "#ffaaaa")


"""
Access Control Entry (ACE) as defined in
https://msdn.microsoft.com/en-us/library/cc230295.aspx
"""
class ACE:
    def __init__(self, data: bytes, trustee_sid: str, object_type: str | None, object_type_flags: int | None, inherited_object_type: str | None, application_data: bytes | None, header: ProtocolHeader):
        self.data = data
        self.trustee_sid = trustee_sid
        self.object_type = object_type
        self.object_type_flags = object_type_flags
        self.inherited_object_type = inherited_object_type
        self.application_data = application_data
        self.header = header

    @classmethod
    def from_bytes_single(cls, data: bytes, offset: int = 0) -> "ACE":
        """
        Parses a signle ACE in an ACL,
        for more info see the following:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a
            - https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acetype?view=net-8.0

        :param data: raw data to parse ace from
        :param offset: position of the ace in the provided data
        :return: tuple consisting of the ace length and the ace itself
        """
        data = data[offset:]

        ace_type, ace_flags, ace_size, access_mask = struct.unpack("<BBHI", data[:8])
        log.debug(f"parsing ace (type: {hex(ace_type)}, flags: {hex(ace_flags)}, size: {hex(ace_size)}, access_mask: {hex(access_mask)})")
        #log.debug(f"raw ace: \n{hexlify(data[:ace_size])}")

        trustee_sid, object_type_flags, object_type, inherited_object_type, application_data = None, None, None, None, None

        # check that ace_type is valid
        if ace_type > 0x0F:
            log.critical(f"Received invalid ACE type {hex(ace_type)}")
            exit(-1)

        match(ace_type):
            # ACCESS_ALLOWED, ACCESS_DENIED
            case 0x00 | 0x01:
                trustee_sid = ProtocolHeader.parse_sid(data, 8)
            # ACCESS_ALLOWED_COMPOUND
            case 0x04:
                raise NotImplementedError("Haven't located the docs yet for ACCESS_ALLOWED_COMPOUND")
            # ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT, ACCESS_ALLOWED_CALLBACK_OBJECT, ACCESS_DENIED_CALLBACK_OBJECT
            # for now ApplicationData is not supported
            case 0x05 | 0x06 | 0x0B | 0x0C:
                object_type_flags = struct.unpack("<I", data[8:12])[0]
                sid_offset = 12
                # ObjectType present
                if object_type_flags & 0x00000001:
                    object_type = ProtocolHeader.parse_guid(data[sid_offset:sid_offset + 16])
                    sid_offset += 16
                # InheritedObjectType present
                if object_type_flags & 0x00000002:
                    inherited_object_type = ProtocolHeader.parse_guid(data[sid_offset:sid_offset + 16])
                    sid_offset += 16
                # ObjectType present
                trustee_sid = ProtocolHeader.parse_sid(data[sid_offset:])
            # ACCESS_ALLOWED_CALLBACK, ACCESS_DENIED_CALLBACK
            # for now ApplicationData is not supported
            case 0x09 | 0x0A:
                trustee_sid = ProtocolHeader.parse_sid(data, 8)
                application_data = None
            case _:
                # some ace types especially ones in the SACL are not supported,
                # as they are not relevant for our purpose.
                # if an unsupported ace is found, we still need to correctly handle all other
                # aces, thus the type will simply be marked as unsupported (none) and all fields will be empty
                log.warning(f"Unsupported ACE type {hex(ace_type)}")
                ace_type = None

        header = ProtocolHeader(data, 2, type=ace_type, flags=ace_flags, size=ace_size, mask=access_mask)
        return cls(data, trustee_sid, object_type, object_type_flags, inherited_object_type, application_data, header)

    @classmethod
    def from_bytes(cls, data: bytes, ace_count: int, offset: int = 0) -> set["ACE"]:
        """
        Parses the ACEs of the ACL,
        for more information see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d06e5a81-176e-46c6-9cf7-9137aad4455e
        Raises an exception if the ace could not be parsed because it is not supported or invalid.

        :param data: raw data to parse the ace from
        :param offset: position of the ace in the provided data
        :return: ace parsed from data
        """
        aces = set()
        for i in range(ace_count):
            ace = ACE.from_bytes_single(data, offset)
            offset += ace.header.size
            if ace.header.type is None:
                log.debug("Skipping ACE because it has no type (unsupported)")
            else:
                aces.add(ace)
        return aces

    @property
    def permissions(self) -> set[str]:
        """
        All permissions that apply to the ACE in str representation
        """
        return {ACE_MASK_DESCRIPTIONS.get(mask)[0] for mask in TRACKED_ACE_MASKS if mask & self.header.mask}

    @property
    def flags(self) -> set[str]:
        """
        All flags that apply to the ACE in str representation
        """
        return {description[0] for flag, description in ACE_FLAG_DESCRIPTIONS.items() if flag & self.header.flags}

    @property
    def allows(self) -> bool:
        """
        Wether the ACE allows access or not

        :return: True if the ACE allows access, False otherwise
        """
        return self.type in ACE_ALLOW_TYPE_DESCRIPTIONS

    @property
    def denies(self) -> bool:
        """
        Wether the ACE denies access or not

        :return: True if the ACE denies access, False otherwise
        """
        return self.type in ACE_DENY_TYPE_DESCRIPTIONS

    @property
    def type(self) -> str | None:
        """
        The type of the ACE in str representation

        :return: the ace type in str representation or None if the type is unknown
        """
        if self.header.type in ACE_TYPE_DESCRIPTIONS:
            return ACE_TYPE_DESCRIPTIONS[self.header.type][0]
        # unknown ace type, returns none
        return None

    @property
    def inherited(self) -> bool:
        """
        Wether the ACE is inherited
        """
        return "INHERITED_ACE" in self.flags

    def __str__(self) -> str:
        return self.header.table()

"""
Discretionary Access Control List (DACL) as defined in
https://msdn.microsoft.com/en-us/library/cc230297.aspx
"""
class DACL:
    def __init__(self, data: bytes, aces: set[ACE], header: ProtocolHeader):
        """
        :param data: raw binary data
        :param aces: set of access control entries
        :param header: header of the DACL
        """
        self.data = data
        self.aces = aces
        self.header = header

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "DACL":
        data = data[offset:]

        revision, sbz1, acl_size, ace_count, sbz2 = struct.unpack("<BBHHH", data[:8])
        header = ProtocolHeader(data=data, header_rows=2, revision=revision, sbz1=sbz1, acl_size=acl_size, ace_count=ace_count, sbz2=sbz2)

        aces = ACE.from_bytes(data, ace_count, 8)

        return cls(data, aces, header)

    @property
    def allow_aces(self) -> set[ACE]:
        """
        Returns all ACEs that allow access
        """
        return {ace for ace in self.aces if ace.allows}

    @property
    def deny_aces(self) -> set[ACE]:
        """
        Returns all ACEs that deny access
        """
        return {ace for ace in self.aces if ace.denies}

    @property
    def by_trustee(self) -> dict[str, set[ACE]]:
        """
        Returns all ACEs sorted by trustee
        """
        sorted = {}
        for ace in self.aces:
            if ace.trustee_sid not in sorted:
                sorted[ace.trustee_sid] = set()
            sorted[ace.trustee_sid].add(ace)
        return sorted

    def __iter__(self):
        return iter(self.aces)

    def __str__(self) -> str:
        return f"[DACL]\n{self.header.table()}\n[ACEs] {{\n\t" + "\n\t".join((str(ace).replace("\n", "\n\t") for ace in self.aces)) + "\n}\n"
