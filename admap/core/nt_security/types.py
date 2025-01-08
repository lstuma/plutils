# ACE types
ACE_ALLOW_TYPE_DESCRIPTIONS = {
    0x00: ("ACCESS_ALLOWED", "Grants the specified access right"),
    0x04: ("ACCESS_ALLOWED_COMPOUND", "Grants the specified access right"),
    0x05: ("ACCESS_ALLOWED_OBJECT", "Grants the specified access right for a specific object"),
    0x09: ("ACCESS_ALLOWED_CALLBACK", "Grants the specified access right"),
    0x0B: ("ACCESS_ALLOWED_CALLBACK_OBJECT", "Grants the specified access right"),
}
ACE_DENY_TYPE_DESCRIPTIONS = {
    0x01: ("ACCESS_DENIED", "Denies the specified access right"),
    0x06: ("ACCESS_DENIED_OBJECT", "Denies the specified access right for a specific object"),
    0x0A: ("ACCESS_DENIED_CALLBACK", "Denies the specified access right"),
    0x0C: ("ACCESS_DENIED_CALLBACK_OBJECT", "Denies the specified access right"),
}
ACE_AUDIT_TYPE_DESCRIPTIONS = {
    0x02: ("SYSTEM_AUDIT", "Generates audit messages for attempts to access the object"),
    0x03: ("SYSTEM_ALARM", "Generates audit messages for attempts to access the object"),
    0x07: ("SYSTEM_AUDIT_OBJECT", "Generates audit messages for attempts to access the object"),
    0x08: ("SYSTEM_ALARM_OBJECT", "Generates audit messages for attempts to access the object"),
    0x0D: ("SYSTEM_AUDIT_CALLBACK", "Generates audit messages for attempts to access the object"),
    0x0E: ("SYSTEM_ALARM_CALLBACK", "Generates audit messages for attempts to access the object"),
    0x0F: ("SYSTEM_AUDIT_CALLBACK_OBJECT", "Generates audit messages for attempts to access the object"),
}
ACE_TYPE_DESCRIPTIONS = {
    **ACE_ALLOW_TYPE_DESCRIPTIONS,
    **ACE_DENY_TYPE_DESCRIPTIONS,
    **ACE_AUDIT_TYPE_DESCRIPTIONS
}

# ACE flags
ACE_FLAG_DESCRIPTIONS = {
    0x01: ("ObjectInherit", "The ACE is inherited by child objects"),
    0x02: ("ContainerInherit", "The ACE is inherited by child containers"),
    0x04: ("NoPropagateInherit", "The ACE is not inherited only by direct child objects"),
    0x08: ("InheritOnly", "The ACE is inherited by child objects but not by the object itself"),
    0x0E: ("InheritanceFlags", "Logical `OR` of ObjectInherit, ContainerInherit, NoPropagateInherit and InheritOnly"),
    0x0F: ("Inherited", "The ACE is inherited"),

    0x40: ("SuccessfulAccess", "Successful access attempts are audited"),
    0x80: ("FailedAccess", "Failed access attempts are audited."),
    0xC0: ("AuditFlags", "All Access attempts are audited"),
}

# ACE masks, see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
# in the form of {mask: (name, description, exploitable)}
# exploitable means that the mask is often exploitable, this might not cover
# all cases and should be used as a hint
ACE_MASK_DESCRIPTIONS = {
    0x00000001: ("DS_CREATE_CHILD", "Create child object"),
    0x00000002: ("DS_DELETE_CHILD", "Delete child object"),
    0x00000004: ("DS_LIST_CONTENTS", "List child objects"),
    0x00000008: ("DS_WRITE_PROPERTY_EXTENDED", "Perform an operation controlled by a validated write access right"),
    0x00000010: ("DS_READ_PROPERTY", "Read properties"),
    0x00000020: ("DS_WRITE_PROPERTY", "Write properties"),
    0x00000040: ("DS_DELETE_TREE", "Delete the object and all child objects"),
    0x00000080: ("DS_LIST_OBJECT", "List the object"),
    0x00000100: ("DS_CONTROL_ACCESS", "Access control"),
    0x00010000: ("DELETE", "Delete the object"),
    0x00020000: ("READ_CONTROL", "Read security descriptor and owner (excluding SACL)"),
    0x00040000: ("WRITE_DAC", "Write DACL"),
    0x00080000: ("WRITE_OWNER", "Write owner"),
    0x10000000: ("GENERIC_ALL", "Generic all access"),
    0x20000000: ("GENERIC_EXECUTE", "Read permissions and list contents of container object"),
    0x40000000: ("GENERIC_WRITE", "Generic write access"),
    0x80000000: ("GENERIC_READ", "Generic read access"),

    0x00100000: ("SYNCHRONIZE", "Synchronize access"),
}
TRACKED_ACE_MASKS = {
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000100,
    0x00010000,
    0x00040000,
    0x00080000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
}

ACE_OBJECT_TYPE_FLAGS = {
    0x00000001: ("ACE_OBJECT_TYPE_PRESENT", "ObjectType is present"),
    0x00000002: ("ACE_INHERITED_OBJECT_TYPE_PRESENT", "InheritedObjectType is present. If this value is not specified, all types of child objects can inherit the ACE"),
}
