// Package sambaacl builds protected Windows ACLs for managed Samba data.
package sambaacl

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

const (
	read           = 0x001200a9
	modify         = 0x001201bf
	deleteObject   = 0x00010000
	deleteChild    = 0x00000040
	readControl    = 0x00020000
	fileAllAccess  = 0x001f01ff
	inheritObjects = 0x01
	inheritDirs    = 0x02
	inheritOnly    = 0x08
)

var levelMasks = [...]uint32{0, read, modify, modify | deleteObject | deleteChild}

// Options selects a normal file/directory, a managed top-level directory, or
// the Data share root. TopLevel and ShareRoot require Directory.
type Options struct {
	Directory bool
	TopLevel  bool
	ShareRoot bool
}

type sid struct {
	name      string
	authority byte
	parts     []uint32
}

func domainSID(value string) (sid, error) {
	rest, ok := strings.CutPrefix(value, "S-1-5-21-")
	if !ok {
		return sid{}, errors.New("expected an AD domain SID")
	}

	fields := strings.Split(rest, "-")
	if len(fields) != 4 {
		return sid{}, errors.New("expected four numeric domain SID components")
	}

	parts := []uint32{21}
	for _, field := range fields {
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return sid{}, fmt.Errorf("invalid domain SID component %q", field)
		}
		parts = append(parts, uint32(n))
	}
	return sid{name: value, authority: 5, parts: parts}, nil
}

func (s sid) size() int { return 8 + 4*len(s.parts) }

type ace struct {
	trustee sid
	flags   byte
	mask    uint32
}

func (a ace) size() int { return 8 + a.trustee.size() }

// Descriptor is an immutable managed ACL. Use NewDescriptor to construct it.
type Descriptor struct {
	admin     sid
	entries   []ace
	directory bool
}

// NewDescriptor validates folder assignments and builds a protected DACL.
// Levels are 0 (hidden), 1 (read), 2 (modify without deletion), or 3 (modify and delete).
func NewDescriptor(levels map[string]int, adminSID string, options Options) (Descriptor, error) {
	admin, err := domainSID(adminSID)
	if err != nil {
		return Descriptor{}, fmt.Errorf("DOMAIN_ADMINS_SID is required for managed folder ACLs: %w", err)
	}

	if !options.Directory && (options.TopLevel || options.ShareRoot) {
		return Descriptor{}, errors.New("top-level and share-root ACLs require a directory")
	}
	if options.ShareRoot && (options.TopLevel || len(levels) != 0) {
		return Descriptor{}, errors.New("the Data share root cannot have individual assignments")
	}

	var flags byte
	if options.Directory {
		flags = inheritObjects | inheritDirs
	}
	descriptor := Descriptor{admin: admin, directory: options.Directory, entries: []ace{
		{trustee: sid{name: "OW", authority: 3, parts: []uint32{4}}, flags: flags, mask: readControl},
		{trustee: sid{name: "SY", authority: 5, parts: []uint32{18}}, flags: flags, mask: fileAllAccess},
		{trustee: admin, flags: flags, mask: fileAllAccess},
	}}

	keys := make([]string, 0, len(levels))
	for name := range levels {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	for _, name := range keys {
		level := levels[name]
		trustee, err := domainSID(name)
		if err != nil || level < 0 || level >= len(levelMasks) {
			return Descriptor{}, fmt.Errorf("invalid stored folder permission for SID %q (level %d)", name, level)
		}
		if level == 0 {
			continue
		}

		mask := levelMasks[level]
		if options.TopLevel {
			// The trustee cannot rename/delete this directory; descendants
			// inherit the full mask for the assigned level.
			descriptor.entries = append(descriptor.entries,
				ace{trustee: trustee, mask: mask &^ deleteObject},
				ace{trustee: trustee, flags: flags | inheritOnly, mask: mask},
			)
		} else {
			descriptor.entries = append(descriptor.entries, ace{trustee: trustee, flags: flags, mask: mask})
		}
	}

	if options.ShareRoot {
		descriptor.entries = append(descriptor.entries, ace{
			trustee: sid{name: "AU", authority: 5, parts: []uint32{11}}, mask: read,
		})
	}
	if descriptor.aclSize() > math.MaxUint16 {
		return Descriptor{}, errors.New("managed Windows ACL exceeds the 16-bit DACL size limit")
	}
	return descriptor, nil
}

// SDDL returns the matching diagnostic SDDL text, or empty for a zero Descriptor.
func (d Descriptor) SDDL() string {
	if d.admin.name == "" {
		return ""
	}

	var result strings.Builder
	fmt.Fprintf(&result, "O:%sG:%sD:P", d.admin.name, d.admin.name)
	for _, entry := range d.entries {
		var flags string
		if entry.flags&(inheritObjects|inheritDirs) != 0 {
			flags = "OICI"
		}
		if entry.flags&inheritOnly != 0 {
			flags += "IO"
		}

		switch entry.mask {
		case readControl:
			fmt.Fprintf(&result, "(A;%s;RC;;;%s)", flags, entry.trustee.name)
		case fileAllAccess:
			fmt.Fprintf(&result, "(A;%s;FA;;;%s)", flags, entry.trustee.name)
		default:
			fmt.Fprintf(&result, "(A;%s;0x%08x;;;%s)", flags, entry.mask, entry.trustee.name)
		}
	}
	return result.String()
}

func (d Descriptor) aclSize() int {
	size := 8
	for _, entry := range d.entries {
		size += entry.size()
	}
	return size
}
