from ldap3 import Entry

class ADRef:
    """
    A wrapper for the ldap entry for an AD object
    """
    def __init__(self, entry: Entry):
        self.entry = entry
        self.shortcuts = {
            "dn": "entry_dn",
            "sid": "objectSid",
            "guid": "objectGUID",
        }
        # name of the object
        self.name = self.entry.entry_dn.split(",")[0].split("=")[1]

        # security descriptor
        self.security_descriptor = None

    def __getattr__(self, item):
        """
        Will first try to get the attribute from the entry, if it fails it will try to convert the snake case attribute to camel case
        """
        attr = None

        # camel case version of attribute
        camel_item = "".join((item.split("_")[0], *(x.capitalize() for x in item.lower().split("_")[1:])))

        if item in self.shortcuts:
            attr = getattr(self.entry, self.shortcuts[item])
        elif hasattr(self.entry, item):
            attr = getattr(self.entry, item)
        elif hasattr(self.entry, camel_item):
            attr = getattr(self.entry, camel_item)
        else:
            # if the attribute is not found, raise an AttributeError
            raise AttributeError(f"Attribute {item} not found in entry (also tried {camel_item} and {self.shortcuts.get(item)})")

        if hasattr(attr, "value"):
            return attr.value
        elif hasattr(attr, "values"):
            return attr.values
        else:
            return attr

    def __hasattr__(self, item):
        # camel case version of attribute
        camel_item = "".join((item.split("_")[0], *(x.capitalize() for x in item.lower().split("_")[1:])))
        return hasattr(self.entry, item) or hasattr(self.entry, camel_item) or item in self.shortcuts


    def __str__(self):
        return self.entry.entry_to_json()
