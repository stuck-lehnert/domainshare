package documents

import (
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"io"
	"os"
	"path/filepath"
)

type tiffProfile struct {
	width, height, orientation    int
	size                          int64
	nextOffset, orientationOffset int64
	nextSize                      int
	orientationValue              []byte
}

func tiffOrientation(source *os.File) int {
	profile, _, err := readTIFFProfile(source)
	if err != nil {
		return 1
	}
	return profile.orientation
}

// Read only the first bounded directory. These values must be validated
// independently of libtiff before allowing it to decode a frame.
func readTIFFProfile(source *os.File) (tiffProfile, bool, error) {
	profile := tiffProfile{orientation: 1}
	var header [16]byte
	if _, err := source.ReadAt(header[:8], 0); err != nil {
		return profile, false, err
	}

	var order binary.ByteOrder
	switch string(header[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return profile, false, nil
	}
	var offset uint64
	countSize, entrySize, tagCountSize, pointerSize := 2, 12, 4, 4
	switch order.Uint16(header[2:4]) {
	case 42:
		offset = uint64(order.Uint32(header[4:8]))
	case 43: // BigTIFF uses 64-bit offsets and counts.
		if order.Uint16(header[4:6]) != 8 || order.Uint16(header[6:8]) != 0 {
			return profile, true, errors.New("invalid BigTIFF header")
		}
		if _, err := source.ReadAt(header[8:], 8); err != nil {
			return profile, true, err
		}
		offset = order.Uint64(header[8:])
		countSize, entrySize, tagCountSize, pointerSize = 8, 20, 8, 8
	default:
		return profile, false, nil
	}

	info, err := source.Stat()
	if err != nil {
		return profile, true, err
	}
	profile.size = info.Size()
	if offset < uint64(pointerSize*2) || offset >= uint64(info.Size()) {
		return profile, true, errors.New("invalid first TIFF directory offset")
	}

	var countData [8]byte
	if _, err := source.ReadAt(countData[:countSize], int64(offset)); err != nil {
		return profile, true, err
	}
	count := uint64(order.Uint16(countData[:2]))
	if countSize == 8 {
		count = order.Uint64(countData[:])
	}
	if count == 0 || count > 4096 {
		return profile, true, errors.New("TIFF first directory exceeds metadata limit")
	}

	entryStart := int64(offset) + int64(countSize)
	entries := make([]byte, entrySize*int(count)+pointerSize)
	if _, err := source.ReadAt(entries, entryStart); err != nil {
		return profile, true, err
	}
	end := entrySize * int(count)
	if next := entries[end:]; anyNonZero(next) {
		profile.nextOffset, profile.nextSize = entryStart+int64(end), pointerSize
	}

	const widthTag, heightTag, orientationTag = 256, 257, 274
	seen := make(map[uint16]bool, 3)
	for entry := range int(count) {
		field := entries[entry*entrySize : (entry+1)*entrySize]
		tag := order.Uint16(field[:2])
		if tag != widthTag && tag != heightTag && tag != orientationTag {
			continue
		}
		if seen[tag] {
			return profile, true, errors.New("ambiguous TIFF dimensions or orientation")
		}
		seen[tag] = true
		length := uint64(order.Uint32(field[4:8]))
		if tagCountSize == 8 {
			length = order.Uint64(field[4:12])
		}
		if length != 1 {
			return profile, true, errors.New("invalid TIFF scalar field")
		}

		valueOffset := 4 + tagCountSize
		value := field[valueOffset:]
		fieldType := order.Uint16(field[2:4])
		number, normalized, valid := tiffScalar(order, fieldType, value)
		if !valid {
			return profile, true, errors.New("unsupported TIFF scalar field type")
		}
		if tag == orientationTag {
			if number >= 2 && number <= 8 {
				profile.orientation = int(number)
				profile.orientationOffset = entryStart + int64(entry*entrySize+valueOffset)
				profile.orientationValue = normalized
			}
			continue
		}
		if number == 0 || number > maximumPixels {
			return profile, true, errors.New("TIFF dimensions exceed pixel limit")
		}
		if tag == widthTag {
			profile.width = int(number)
		} else {
			profile.height = int(number)
		}
	}
	if profile.width <= 0 || profile.height <= 0 || profile.width > maximumPixels/profile.height {
		return profile, true, errors.New("TIFF exceeds pixel limit")
	}
	return profile, true, nil
}

func anyNonZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return true
		}
	}
	return false
}

func tiffScalar(order binary.ByteOrder, kind uint16, value []byte) (uint64, []byte, bool) {
	// A second return value encodes the same field with an orientation of 1.
	normalized := make([]byte, len(value))
	switch kind {
	case 3: // SHORT
		order.PutUint16(normalized, 1)
		return uint64(order.Uint16(value)), normalized, true
	case 4: // LONG
		order.PutUint32(normalized, 1)
		return uint64(order.Uint32(value)), normalized, true
	case 16: // LONG8, permitted only in BigTIFF.
		if len(value) == 8 {
			order.PutUint64(normalized, 1)
			return order.Uint64(value), normalized, true
		}
	}
	return 0, nil, false
}

// The Go decoder covers ordinary TIFFs. Preserve legacy compressed/BigTIFF
// compatibility in the same restricted helper, after enforcing dimensions
// and selecting only the first image. No live original is changed.
func decodeFallbackTIFF(source *os.File, profile tiffProfile) (image.Image, error) {
	directory := filepath.Dir(source.Name())
	sourcePath := source.Name()
	if profile.nextSize != 0 || profile.orientationOffset != 0 {
		first, err := os.CreateTemp(directory, ".tiff-first-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(first.Name())
		copyErr := writeFirstTIFFPage(first, source, profile)
		if err := errors.Join(copyErr, first.Close()); err != nil {
			return nil, err
		}
		sourcePath = first.Name()
	}

	converted, err := os.CreateTemp(directory, ".tiff-rgba-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(converted.Name())
	if err := converted.Close(); err != nil {
		return nil, err
	}
	if _, err := extractionCommand(120, "tiff2rgba", "-M", "128", "-b", "-c", "none", sourcePath, converted.Name()); err != nil {
		return nil, err
	}

	preview, err := os.Open(converted.Name())
	if err != nil {
		return nil, err
	}
	defer preview.Close()
	if info, err := preview.Stat(); err != nil || info.Size() > 128<<20 {
		return nil, errors.New("TIFF conversion exceeds size limit")
	}
	config, format, err := image.DecodeConfig(preview)
	if err != nil || format != "tiff" || config.Width != profile.width || config.Height != profile.height {
		return nil, errors.New("invalid first-page dimensions from TIFF conversion")
	}
	if _, err := preview.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, _, err := image.Decode(preview)
	if err != nil {
		return nil, err
	}
	return orientTIFF(data, profile.orientation), nil
}

func writeFirstTIFFPage(target *os.File, source *os.File, profile tiffProfile) error {
	if _, err := io.CopyN(target, io.NewSectionReader(source, 0, profile.size), profile.size); err != nil {
		return err
	}
	if profile.nextSize != 0 {
		if _, err := target.WriteAt(make([]byte, profile.nextSize), profile.nextOffset); err != nil {
			return err
		}
	}
	if profile.orientationOffset != 0 {
		_, err := target.WriteAt(profile.orientationValue, profile.orientationOffset)
		return err
	}
	return nil
}

type tiffView struct {
	image.Image
	bounds               image.Rectangle
	origin, xStep, yStep image.Point
}

func (view tiffView) Bounds() image.Rectangle { return view.bounds }

func (view tiffView) At(x, y int) color.Color {
	if !image.Pt(x, y).In(view.bounds) {
		return color.NRGBA{}
	}
	pos := view.origin.Add(view.xStep.Mul(x)).Add(view.yStep.Mul(y))
	return view.Image.At(pos.X, pos.Y)
}

func orientTIFF(source image.Image, orientation int) image.Image {
	if orientation < 2 || orientation > 8 {
		return source
	}

	bound := source.Bounds()
	w, h := bound.Dx(), bound.Dy()
	view := tiffView{Image: source, bounds: image.Rect(0, 0, w, h), origin: bound.Min,
		xStep: image.Pt(1, 0), yStep: image.Pt(0, 1)}
	if orientation >= 5 {
		view.bounds = image.Rect(0, 0, h, w)
		view.xStep, view.yStep = view.yStep, view.xStep
	}

	switch orientation {
	case 2:
		view.origin.X += w - 1
		view.xStep.X = -1
	case 3:
		view.origin = view.origin.Add(image.Pt(w-1, h-1))
		view.xStep.X, view.yStep.Y = -1, -1
	case 4:
		view.origin.Y += h - 1
		view.yStep.Y = -1
	case 6:
		view.origin.Y += h - 1
		view.xStep.Y = -1
	case 7:
		view.origin = view.origin.Add(image.Pt(w-1, h-1))
		view.xStep.Y, view.yStep.X = -1, -1
	case 8:
		view.origin.X += w - 1
		view.yStep.X = -1
	}

	return view
}
