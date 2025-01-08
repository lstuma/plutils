from plutils.log import Logger
from admap.core import LDAPConnection, ADRef
from admap.core.nt_security import NTSecurityDescriptor
from ms_active_directory import ADDomain
from ldap3 import NTLM, Server
from pyvis.network import Network
import networkx as nx

log  = Logger(__name__, color="green")

class ActiveDirectory:
    def __init__(self, domain, ntlm_username, password, ldap_port=389, use_ssl=False):
        # ldap connection
        self.conn = LDAPConnection(domain, ldap_port, ntlm_username, password, use_ssl)

        # ms_active_directory domain (for further features and well-known objects)
        self.domain = ADDomain(
            domain,
            ldap_servers_or_uris=[self.conn.server],
            encrypt_connections=use_ssl,
            discover_ldap_servers=False,
            discover_kerberos_servers = False,
        )
        self.session = self.domain.create_session_as_user(ntlm_username, password, authentication_mechanism=NTLM)

        # all sids
        self.sids: set[str] = {entry.objectSid.value for entry in self.conn.search(attributes=["objectSid"]) if hasattr(entry, "objectSid") and entry.objectSid}

        # References to all objects in the active directory
        self.refs: set[ADRef] = set()

        self.map: dict[str, ADRef] = {}
        self._guid_map: dict[str, ADRef] = {}

    def test(self):
        import logging
        import plutils.log as pl_log
        log.info("Test function")
        log.debug(f"Connected to {self.domain}")
        self.__gather()
        log.debug("Generating and saving graph")
        self.save_pyvis("/tmp/graph.html")

    def save_pyvis(self, path: str, height: str = "1080px", width: str = "100%"):
        """
        Save the active directory graph as a pyvis html file

        :param path: the path to save the html file
        :param height: the height of the graph
        :param width: the width of the graph
        """
        log.info(f"Saving graph to {path}")
        net = Network(height=height, width=width, directed=True)
        graph = self.graph_networkx()
        net.from_nx(graph)
        net.repulsion(node_distance=1000, spring_length=2000, central_gravity=0.1)
        net.show(path, notebook=False)

    def graph_networkx(self):
        """
        Create a networkx graph of the active directory
        """
        log.debug("Creating networkx graph of the active directory")
        graph = nx.DiGraph()
        log.debug("Adding nodes")
        for ref in self.map.values():
            log.debug(f"Adding node {ref.name} ({ref.sid})")
            graph.add_node(ref.sid, size=20, label=ref.name, title=ref.sid)
        log.debug("Adding edges")
        for ref in self.map.values():
            if ref.security_descriptor:
                for ace in ref.security_descriptor.dacl:
                    if ace.trustee_sid in self.map:
                        log.debug(f"Adding edge from {ref.name} to {ace.trustee_sid}")
                        graph.add_edge(ref.sid, ace.trustee_sid, label=str(ace.permissions))
                    else:
                        log.error(f"Could not find ACE trustee {ace.trustee_sid}")
        return graph


    def __gather(self):
        """
        Gather all objects in the active directory
        """
        log.debug("Gathering all objects in the active directory")
        log.debug("Gathering objects (using ldap3)")
        entries = self.conn.search()
        self.refs = {ADRef(entry) for entry in entries if entry.objectSid}
        log.debug(f"Found {len(entries)} objects (with SIDs)")
        self.map = {ref.sid: ref for ref in self.refs}

        log.debug("Gathering objects (using ms_active_directory)")

        for sid in self.sids:
            object = self.session.find_object_by_sid(sid)
            if not object:
                log.critical(f"Could not find object with sid {sid}")
                exit()
            sd = self.session.find_security_descriptor_for_object(object)
            log.debug(f"Found {object.distinguished_name if not hasattr(object, "name") else object.name} ({object.__class__.__name__})")
            if sd:
                object.security_descriptor = sd
                log.debug(f"Found sd: {sd["Dacl"]["AclRevision"]} ({sd.__class__.__name__})")
                #log.debug(object.security_descriptor)
            self.map[sid] = object
        return


        entries = self.conn.search()
        self.refs = {ADRef(entry) for entry in entries}
        log.debug(f"Found {len(entries)} objects")

        self.map = {ref.sid: ref for ref in self.refs if ref.sid}
        self._guid_map = {ref.guid: ref for ref in self.refs if ref.guid}

        # gather the NT security descriptor of all objects
        self.__gather_nt_security()

    def __gather_nt_security(self):
        """
        Gather the NT security descriptor of all objects in the active directory
        """
        log.debug("Gathering the NT security descriptor of all objects in the active directory")
        for ref in self.refs:
            sd = self.conn.get_ad_security_descriptor(ref.dn)
            if sd:
                ref.security_descriptor = NTSecurityDescriptor.from_bytes(sd)
                log.debug(f"Found security descriptor for {ref.name} ({ref.sid})")
