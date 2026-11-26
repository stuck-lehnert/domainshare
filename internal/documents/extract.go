package documents

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/unicode"
)

const maximumPixels = 25_000_000

type extractionConfig struct {
	Extension    string `json:"extension"`
	Phase        string `json:"phase"`
	Language     string `json:"language"`
	MaxPages     int    `json:"max_pages"`
	Timeout      int    `json:"timeout"`
	DPI          int    `json:"ocr_dpi"`
	MaxDimension int    `json:"ocr_max_dimension"`
	PageTimeout  int    `json:"ocr_page_timeout"`
}

type extractionResult struct {
	Body     string `json:"body"`
	Pages    int    `json:"pages"`
	NeedsOCR bool   `json:"needsOcr"`
	Error    string `json:"error,omitempty"`
	preview  string
}

// RunExtractHelper is exclusively a one-shot subprocess entry point. The
// parent already dropped credentials. Fail closed before reading any document.
func RunExtractHelper(workspace string) int {
	if !filepath.IsAbs(workspace) || os.Geteuid() == 0 {
		return 1
	}
	if err := os.Chdir(workspace); err != nil {
		return 1
	}
	configFile, _, err := openFile(workspace, "config.json", nil)
	if err != nil {
		return 1
	}
	var config extractionConfig
	err = json.NewDecoder(io.LimitReader(configFile, 4096)).Decode(&config)
	configFile.Close()
	if err != nil || config.Timeout < 1 || config.Timeout > 3600 {
		return 1
	}

	result := extractionResult{}
	if err = extractionSandbox(workspace, config.Timeout); err == nil {
		result, err = extractDocument(config)
	}
	if err != nil {
		result = extractionResult{Error: limitRunes(err.Error(), 200)}
	}
	resultFile, err := os.OpenFile("result.json", os.O_WRONLY|os.O_EXCL|os.O_CREATE, 0o600)
	if err != nil {
		return 1
	}
	err = json.NewEncoder(resultFile).Encode(result)
	closeErr := resultFile.Close()
	if err != nil || closeErr != nil || result.Error != "" {
		return 1
	}
	return 0
}

type limitedOutput struct {
	bytes.Buffer
	remaining int
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	if len(data) > output.remaining {
		return 0, errors.New("document command output is too large")
	}
	output.remaining -= len(data)
	return output.Buffer.Write(data)
}

func extractionCommand(seconds int, command string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	out := &limitedOutput{remaining: maxText * 4}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s timed out", command)
		}
		return "", fmt.Errorf("%s failed: %w", command, err)
	}
	return strings.ToValidUTF8(out.String(), "\ufffd"), nil
}

func readExtractedText(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxText))
	if err != nil {
		return "", err
	}
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		return unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().String(string(data))
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	return strings.ToValidUTF8(string(data), "\ufffd"), nil
}

func extractDocument(config extractionConfig) (extractionResult, error) {
	switch {
	case config.Extension == ".pdf":
		return extractPDF(config)
	case contentType(config.Extension):
		body, err := extractOffice("input")
		return extractionResult{Body: body}, err
	case imageType(config.Extension):
		return extractionResult{}, extractImage("input", "preview.jpg")
	default:
		return extractionResult{}, errors.New("file type is not eligible for content extraction")
	}
}

func extractOffice(path string) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()

	remaining := uint64(64 << 20)
	if len(archive.File) > 10_000 {
		return "", errors.New("Office document exceeds extraction limits")
	}
	for _, entry := range archive.File {
		if entry.UncompressedSize64 > remaining {
			return "", errors.New("Office document exceeds extraction limits")
		}
		remaining -= entry.UncompressedSize64
	}
	sort.SliceStable(archive.File, func(i, j int) bool { return archive.File[i].Name < archive.File[j].Name })
	var text []string
	length := 0
	for _, entry := range archive.File {
		wanted := strings.HasPrefix(entry.Name, "word/") || strings.HasPrefix(entry.Name, "ppt/slides/") || entry.Name == "content.xml"
		if !wanted || !strings.HasSuffix(entry.Name, ".xml") || entry.UncompressedSize64 > 16<<20 {
			continue
		}
		fragment, err := officeXML(entry)
		if err != nil {
			return "", err
		}
		text = append(text, fragment)
		length += utf8.RuneCountInString(fragment) + 1
		if length > maxText {
			break
		}
	}
	return limitRunes(strings.Join(text, "\n"), maxText), nil
}

func officeXML(entry *zip.File) (string, error) {
	file, err := entry.Open()
	if err != nil {
		return "", err
	}
	defer file.Close()

	decoder := officeXMLDecoder(io.LimitReader(file, (16<<20)+1))
	var text, fragment strings.Builder
	var haveFragment bool
	flush := func() {
		if fragment.Len() == 0 {
			return
		}
		if haveFragment {
			text.WriteByte(' ')
		}
		haveFragment = true
		text.WriteString(fragment.String())
		fragment.Reset()
	}
	depth, roots := 0, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		switch value := token.(type) {
		case xml.StartElement:
			flush()
			if depth == 0 {
				roots++
			}
			depth++
		case xml.EndElement:
			flush()
			depth--
		case xml.CharData:
			if depth > 0 {
				fragment.Write(value)
			} else if len(bytes.TrimSpace(value)) != 0 {
				return "", errors.New("invalid text outside Office XML document")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return "", errors.New("invalid Office XML")
	}
	return text.String(), nil
}

func officeXMLDecoder(input io.Reader) *xml.Decoder {
	reader := bufio.NewReader(input)
	prefix, _ := reader.Peek(4)
	var source io.Reader = reader
	var predecodedUTF16 bool
	switch {
	case bytes.HasPrefix(prefix, []byte{0xff, 0xfe}), bytes.HasPrefix(prefix, []byte{0xfe, 0xff}):
		source = unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Reader(reader)
		predecodedUTF16 = true
	case bytes.HasPrefix(prefix, []byte{'<', 0, '?', 0}):
		source = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Reader(reader)
		predecodedUTF16 = true
	case bytes.HasPrefix(prefix, []byte{0, '<', 0, '?'}):
		source = unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder().Reader(reader)
		predecodedUTF16 = true
	case bytes.HasPrefix(prefix, []byte{0xef, 0xbb, 0xbf}):
		_, _ = reader.Discard(3)
	}

	decoder := xml.NewDecoder(source)
	decoder.CharsetReader = func(name string, input io.Reader) (io.Reader, error) {
		if predecodedUTF16 && strings.HasPrefix(strings.ToLower(name), "utf-16") {
			return input, nil
		}
		charset, err := htmlindex.Get(name)
		if err != nil {
			return nil, err
		}
		return charset.NewDecoder().Reader(input), nil
	}
	return decoder
}

func extractImage(path, preview string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	imageData, err := loadPreviewImage(file)
	if err != nil {
		return err
	}

	width, height := imageData.Bounds().Dx(), imageData.Bounds().Dy()
	if biggest := max(width, height); biggest > 1400 {
		width = max(1, int(math.Round(float64(width)*1400/float64(biggest))))
		height = max(1, int(math.Round(float64(height)*1400/float64(biggest))))
	}
	thumb := image.NewNRGBA(image.Rect(0, 0, width, height))
	draw.CatmullRom.Scale(thumb, thumb.Bounds(), imageData, imageData.Bounds(), draw.Src, nil)
	// Pillow's RGB conversion drops alpha without compositing onto black.
	for i := 3; i < len(thumb.Pix); i += 4 {
		thumb.Pix[i] = 255
	}
	output, err := os.OpenFile(preview, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = jpeg.Encode(output, thumb, &jpeg.Options{Quality: 85})
	return errors.Join(err, output.Close())
}

func loadPreviewImage(file *os.File) (image.Image, error) {
	metadata, format, err := image.DecodeConfig(file)
	if err != nil {
		// BigTIFF is not registered in the Go decoder at all.
		profile, recognized, profileErr := readTIFFProfile(file)
		if !recognized {
			return nil, err
		}
		if profileErr != nil {
			return nil, profileErr
		}
		return decodeFallbackTIFF(file, profile)
	}
	if metadata.Width <= 0 || metadata.Height <= 0 || metadata.Width > maximumPixels/metadata.Height {
		return nil, errors.New("image exceeds pixel limit")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	imageData, _, err := image.Decode(file)
	if err != nil {
		if format != "tiff" {
			return nil, err
		}
		profile, _, profileErr := readTIFFProfile(file)
		if profileErr != nil {
			return nil, profileErr
		}
		return decodeFallbackTIFF(file, profile)
	}
	if bounds := imageData.Bounds(); bounds.Dx() != metadata.Width || bounds.Dy() != metadata.Height {
		return nil, errors.New("decoded image dimensions differ from its header")
	}
	// Pillow applies TIFF orientation to the first frame, but leaves EXIF
	// orientation alone for JPEG, PNG and WebP.
	if format == "tiff" {
		imageData = orientTIFF(imageData, tiffOrientation(file))
	}

	return imageData, nil
}

var (
	pdfPages = regexp.MustCompile(`(?m)^Pages:\s*(\d+)`)
	pdfSize  = regexp.MustCompile(`Page\s+(\d+)\s+size:\s+([0-9.]+)\s+x\s+([0-9.]+)\s+pts`)
)

func extractPDF(config extractionConfig) (extractionResult, error) {
	info, err := extractionCommand(120, "pdfinfo", "input")
	if err != nil {
		return extractionResult{}, err
	}
	pages := 0
	if match := pdfPages.FindStringSubmatch(info); len(match) != 0 {
		pages, err = strconv.Atoi(match[1])
		if err != nil || pages > config.MaxPages {
			return extractionResult{}, errors.New("PDF exceeds page limit")
		}
	}
	if _, err := extractionCommand(120, "pdftotext", "-enc", "UTF-8", "-layout", "input", "text.txt"); err != nil {
		return extractionResult{}, err
	}
	body, err := readExtractedText("text.txt")
	if err != nil {
		return extractionResult{}, err
	}
	images, err := extractionCommand(120, "pdfimages", "-list", "input")
	if err != nil {
		return extractionResult{}, err
	}
	candidates := ocrCandidates(body, images, pages)
	if config.Phase == "ocr" {
		fragment, err := recognizePDF(candidates, config)
		if err != nil {
			return extractionResult{}, err
		}
		if fragment != "" {
			body = strings.TrimRightFunc(body, unicodeSpace) + "\n" + fragment
		}
		return extractionResult{Body: limitRunes(body, maxText), Pages: pages}, nil
	}
	_, err = extractionCommand(120, "pdftoppm", "-f", "1", "-l", "1", "-singlefile", "-scale-to", "1400",
		"-jpeg", "input", "preview")
	return extractionResult{Body: body, Pages: pages, NeedsOCR: len(candidates) != 0}, err
}

func ocrCandidates(body, images string, pages int) []int {
	imagePages := make(map[int]bool)
	for _, line := range strings.Split(images, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[2] == "image" {
			if page, err := strconv.Atoi(fields[0]); err == nil {
				imagePages[page] = true
			}
		}
	}
	var result []int
	for i, text := range strings.Split(body, "\f") {
		if i >= pages {
			break
		}
		if !imagePages[i+1] {
			continue
		}
		count := 0
		for _, r := range text {
			if !unicodeSpace(r) {
				count++
			}
			if count == 80 {
				break
			}
		}
		if count < 80 {
			result = append(result, i+1)
		}
	}
	return result
}

func recognizePDF(pages []int, config extractionConfig) (string, error) {
	if len(pages) == 0 {
		return "", nil
	}
	lastPage := strconv.Itoa(pages[len(pages)-1])
	info, err := extractionCommand(120, "pdfinfo", "-f", "1", "-l", lastPage, "input")
	if err != nil {
		return "", err
	}
	dimensions := make(map[int]float64)
	for _, match := range pdfSize.FindAllStringSubmatch(info, -1) {
		page, _ := strconv.Atoi(match[1])
		width, _ := strconv.ParseFloat(match[2], 64)
		height, _ := strconv.ParseFloat(match[3], 64)
		dimensions[page] = max(width, height)
	}

	var text []string
	length := 0
	dpi := strconv.Itoa(config.DPI)
	for _, page := range pages {
		size := config.MaxDimension
		if dimension, ok := dimensions[page]; ok {
			size = max(1, int(min(float64(size), math.Ceil(dimension*float64(config.DPI)/72))))
		}
		number := strconv.Itoa(page)
		_, err := extractionCommand(config.PageTimeout, "pdftoppm", "-f", number, "-l", number, "-singlefile",
			"-r", dpi, "-scale-to", strconv.Itoa(size), "-gray", "-png", "input", "ocr-page")
		if err != nil {
			return "", err
		}
		fragment, err := extractionCommand(config.PageTimeout, "tesseract", "ocr-page.png", "stdout", "-l", config.Language, "--dpi", dpi)
		if err != nil {
			return "", err
		}
		fragment = strings.TrimFunc(fragment, unicodeSpace)
		if fragment != "" {
			text = append(text, fragment)
			length += utf8.RuneCountInString(fragment) + 1
			if length >= maxText {
				break
			}
		}
	}
	return limitRunes(strings.Join(text, "\n"), maxText), nil
}
