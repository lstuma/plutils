from plutils.log import Logger
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.abstract.entry import Entry

log = Logger(__name__, "green")

class LDAPConnection:
    def __init__(self, server, port, username, password, use_ssl=False):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        log.debug(f"Connecting to {server}:{port} as {username}:{password}..")
        self.server = Server(self.server, port=self.port, get_info=ALL, use_ssl=self.use_ssl)
        self.conn = Connection(self.server, user=self.username, password=self.password, authentication=NTLM, auto_bind=True)
        log.debug("Connection established")

        self._ad_root = None

    @staticmethod
    def ensure_connection(func):
        # decorator to ensure the connection is bound before calling the function
        def wrapper(self, *args, **kwargs):
            if not self.conn.bound:
                self.conn.bind()
            return func(self, *args, **kwargs)
        return wrapper

    @ensure_connection
    def search(self, base: str | None = None, filter: str | None = None, scope: str | None = None, attributes: list[str] | None = None, controls = None) -> list[Entry]:
        """
        Search the LDAP server for entries
        """
        search_base = base or self.ad_root
        search_filter = filter or "(objectClass=*)"
        search_scope = scope or SUBTREE
        attributes = attributes or ['*', 'objectSid', 'objectGUID']
        self.conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
            controls=controls
            )
        return self.conn.entries

    @ensure_connection
    def get_ad_security_descriptor(self, dn: str):
        """
        Get the security descriptor of an active directory object, given its distinguished name.
        Keep in mind that this method only tries to get the DACL of the object.

        :param dn: the distinguished name of the object
        """
        entries = self.search(
            base=dn,
            attributes=['ntSecurityDescriptor'],
            controls = security_descriptor_control(sdflags=0x04)
        )
        if entries:
            entry = entries[0]
            return entry['ntSecurityDescriptor'].value
        return None

    @property
    def ad_root(self) -> str:
        """
        Get the root entry of the active directory
        """
        if not self._ad_root:
            self.conn.search(search_base='', search_scope='BASE', attributes=['namingContexts'], search_filter='(objectClass=*)')
            self._ad_root = self.conn.entries[0].namingContexts[0]
        return self._ad_root
