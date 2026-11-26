package sambaacl

import (
	"encoding/binary"
	"errors"
)

func (s sid) appendBinary(dst []byte) []byte {
	// Revision and count, then a six-byte big-endian SID authority, then
	// the little-endian uint32 subauthorities.
	dst = append(dst, 1, byte(len(s.parts)), 0, 0, 0, 0, 0, s.authority)
	for _, part := range s.parts {
		dst = binary.LittleEndian.AppendUint32(dst, part)
	}
	return dst
}

// Pack serializes the managed descriptor as Samba's xattr_NTACL version 1.
func (d Descriptor) Pack() ([]byte, error) {
	if d.admin.name == "" {
		return nil, errors.New("uninitialized Samba ACL descriptor")
	}

	const (
		ntaclVersion       = 1
		firstUniquePointer = 0x00020000
		ntaclHeaderSize    = 8
		descriptorSize     = 20
		control            = 0x9004 // SELF_RELATIVE | DACL_PROTECTED | DACL_PRESENT
	)
	owner := uint32(ntaclHeaderSize + descriptorSize)
	group := owner + uint32(d.admin.size())
	dacl := group + uint32(d.admin.size())
	aclSize := d.aclSize()
	order := binary.LittleEndian

	// Samba librpc/idl/xattr.idl: uint16 version, a uint16 union selector,
	// then the v1 arm's uint32 unique pointer to the security descriptor.
	out := make([]byte, 0, int(dacl)+aclSize)
	out = order.AppendUint16(out, ntaclVersion)
	out = order.AppendUint16(out, ntaclVersion)
	out = order.AppendUint32(out, firstUniquePointer)

	out = append(out, 1, 0) // security descriptor revision and padding
	out = order.AppendUint16(out, control)
	for _, offset := range []uint32{owner, group, 0, dacl} {
		// Samba's NDR relative pointers are measured from the blob start.
		out = order.AppendUint32(out, offset)
	}

	out = d.admin.appendBinary(out) // owner
	out = d.admin.appendBinary(out) // primary group
	out = append(out, 4, 0)         // Samba SDDL parser's ACL revision and padding
	out = order.AppendUint16(out, uint16(aclSize))
	out = order.AppendUint16(out, uint16(len(d.entries)))
	out = order.AppendUint16(out, 0)
	for _, entry := range d.entries {
		out = append(out, 0, entry.flags) // ACCESS_ALLOWED_ACE_TYPE
		out = order.AppendUint16(out, uint16(entry.size()))
		out = order.AppendUint32(out, entry.mask)
		out = entry.trustee.appendBinary(out)
	}
	return out, nil
}
