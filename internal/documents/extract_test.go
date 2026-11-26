package documents

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/tiff"
	"golang.org/x/sys/unix"
)

func TestExtractorChild(t *testing.T) {
	if workspace := os.Getenv("DOMAINSHARE_TEST_EXTRACT"); workspace != "" {
		os.Exit(RunExtractHelper(workspace))
	}
	if workspace := os.Getenv("DOMAINSHARE_TEST_CONFINEMENT"); workspace != "" {
		outside := filepath.Join(filepath.Dir(workspace), "outside")
		if _, err := os.ReadFile(outside); err != nil {
			t.Fatal(err)
		}
		if err := extractionSandbox(workspace, 30); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(outside); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("read outside workspace: %v", err)
		}
		if err := exec.Command("/usr/bin/cat", outside).Run(); err == nil {
			t.Fatal("child process read outside workspace")
		}
		if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); !errors.Is(err, unix.EPERM) {
			if fd >= 0 {
				unix.Close(fd)
			}
			t.Fatalf("socket: %v", err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "output"), []byte("allowed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func requireExtractionIsolation(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("test invokes helper as current unprivileged user; production helper refuses UID 0")
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION); errno != 0 {
		t.Skipf("test kernel lacks Landlock: %v", errno)
	}
}

func extractTestEnvironment(workspace string) []string {
	return []string{"LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + workspace,
		"TMPDIR=" + workspace, "OMP_THREAD_LIMIT=1", "GOMAXPROCS=1", "PYTHONDONTWRITEBYTECODE=1"}
}

func TestNativeExtractorConfinement(t *testing.T) {
	requireExtractionIsolation(t)
	root := t.TempDir()
	putDocumentFile(t, root, "outside", "sentinel", 0o644)
	workspace := filepath.Join(root, "job")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExtractorChild$")
	cmd.Env = append(extractTestEnvironment(workspace), "DOMAINSHARE_TEST_CONFINEMENT="+workspace)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox test %v\n%s", err, output)
	}
}

func runNativeExtractor(t *testing.T, config extractionConfig, input []byte) (extractionResult, string) {
	t.Helper()
	requireExtractionIsolation(t)
	workspace := createExtractorFixture(t, config, input)
	ctx, cancel := context.WithTimeout(t.Context(), time.Duration(config.Timeout+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExtractorChild$")
	cmd.Env = append(extractTestEnvironment(workspace), "DOMAINSHARE_TEST_EXTRACT="+workspace)
	output, runErr := cmd.CombinedOutput()
	var result extractionResult
	data, err := os.ReadFile(filepath.Join(workspace, "result.json"))
	if err != nil || json.Unmarshal(data, &result) != nil || runErr != nil && result.Error == "" {
		t.Fatalf("extract helper: result %q, read %v, process %v\n%s", data, err, runErr, output)
	}
	return result, workspace
}

func createExtractorFixture(t *testing.T, config extractionConfig, input []byte) string {
	t.Helper()
	workspace := t.TempDir()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "input"), input, 0o400); err != nil {
		t.Fatal(err)
	}
	return workspace
}

func extractionParity(t *testing.T, config extractionConfig, input []byte, native extractionResult) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		return
	}
	reference, err := filepath.Abs("../../app/extract_document.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(reference); err != nil {
		return
	}
	workspace := createExtractorFixture(t, config, input)
	ctx, cancel := context.WithTimeout(t.Context(), time.Duration(config.Timeout+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", reference, workspace)
	cmd.Env = extractTestEnvironment(workspace)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reference extractor: %v\n%s", err, output)
	}
	var baseline extractionResult
	data, err := os.ReadFile(filepath.Join(workspace, "result.json"))
	if err != nil || json.Unmarshal(data, &baseline) != nil || !reflect.DeepEqual(baseline, native) {
		t.Fatalf("native %+v differs from Python %q (%v)", native, data, err)
	}
}

func TestNativeOfficeAndImageExtraction(t *testing.T) {
	var office bytes.Buffer
	archive := zip.NewWriter(&office)
	for _, entry := range []struct{ path, body string }{
		{"word/z.xml", `<p xmlns:w="local"><w:t>Résumé</w:t> und <w:t>Straße</w:t></p>`},
		{"word/a.xml", `<p>erster<!-- comment --> Block</p>`},
		{"elsewhere.txt", "ignore"},
	} {
		file, err := archive.Create(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	config := extractionConfig{Extension: ".docx", Phase: "text", Timeout: 30, MaxPages: 500}
	result, _ := runNativeExtractor(t, config, office.Bytes())
	if result.Error != "" || result.Body != "erster Block\nRésumé  und  Straße" || result.Pages != 0 || result.NeedsOCR {
		t.Fatalf("Office extractor: %+v", result)
	}
	extractionParity(t, config, office.Bytes(), result)

	var raster bytes.Buffer
	if err := tiff.Encode(&raster, image.NewGray(image.Rect(0, 1450, 1800, 2350)), nil); err != nil {
		t.Fatal(err)
	}
	config.Extension = ".tiff"
	result, workspace := runNativeExtractor(t, config, raster.Bytes())
	if result != (extractionResult{}) {
		t.Fatalf("image extractor should not extract text: %+v", result)
	}
	file, err := os.Open(filepath.Join(workspace, "preview.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	dimensions, err := jpeg.DecodeConfig(file)
	if err != nil || dimensions.Width != 1400 || dimensions.Height != 700 {
		t.Fatalf("image preview dimensions %+v, %v", dimensions, err)
	}
}

func TestLegacyTIFFPreviewUsesFirstFrameOrientation(t *testing.T) {
	if _, err := exec.LookPath("tiff2rgba"); err != nil {
		t.Skip("libtiff tools are not installed")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python is only used to generate legacy TIFF fixtures")
	}
	if err := exec.CommandContext(t.Context(), "python3", "-c", "from PIL import Image").Run(); err != nil {
		t.Skip("Pillow is only used to generate legacy TIFF fixtures")
	}

	const fixtureScript = `
import pathlib, sys
from PIL import Image

root = pathlib.Path(sys.argv[1])
image = Image.new('RGB', (120, 60), 'blue')
image.paste('red', (0, 0, 60, 60))
second = Image.new('RGB', (25, 25), 'green')
exif = Image.Exif()
exif[274] = 6
for name, options in [('raw', {}), ('compressed', {'compression': 'jpeg'}), ('big', {'big_tiff': True})]:
    path = root / (name + '.tiff')
    image.save(path, save_all=True, append_images=[second], exif=exif, **options)
    with Image.open(path) as extracted:
        extracted.thumbnail((1400,1400))
        extracted.convert('RGB').save(root / (name + '.jpg'), 'JPEG', quality=85)
`
	root := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "python3", "-c", fixtureScript, root)
	cmd.Env = extractTestEnvironment(root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create TIFF fixture: %v\n%s", err, output)
	}

	readImage := func(path string) image.Image {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		data, err := jpeg.Decode(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	for _, name := range []string{"raw", "compressed", "big"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join(root, name+".tiff"))
			if err != nil {
				t.Fatal(err)
			}
			config := extractionConfig{Extension: ".tiff", Phase: "text", Timeout: 30, MaxPages: 10}
			result, workspace := runNativeExtractor(t, config, input)
			if result != (extractionResult{}) {
				t.Fatalf("TIFF extraction result %+v", result)
			}

			native := readImage(filepath.Join(workspace, "preview.jpg"))
			baseline := readImage(filepath.Join(root, name+".jpg"))
			if native.Bounds() != baseline.Bounds() || native.Bounds() != image.Rect(0, 0, 60, 120) {
				t.Fatalf("preview sizes: Go %v, Pillow %v", native.Bounds(), baseline.Bounds())
			}
			for _, y := range []int{15, 90} {
				r, g, b, _ := native.At(25, y).RGBA()
				wr, wg, wb, _ := baseline.At(25, y).RGBA()
				if absDifference(r, wr)+absDifference(g, wg)+absDifference(b, wb) > 12_000 {
					t.Fatalf("preview colors differ at row %d: Go %v, Pillow %v", y, native.At(25, y), baseline.At(25, y))
				}
			}
		})
	}
}

func absDifference(a, b uint32) uint32 { return max(a, b) - min(a, b) }

func TestNativePDFTextAndScanOCR(t *testing.T) {
	for _, program := range []string{"pdfinfo", "pdftotext", "pdfimages", "pdftoppm", "tesseract"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skipf("%s is not installed", program)
		}
	}
	config := extractionConfig{Extension: ".pdf", Phase: "text", Timeout: 45, Language: "eng",
		MaxPages: 20, DPI: 300, MaxDimension: 1600, PageTimeout: 15}
	textPDF := pdfFixture(t, false)
	result, workspace := runNativeExtractor(t, config, textPDF)
	if result.Error != "" || result.Pages != 1 || result.NeedsOCR || !strings.Contains(result.Body, "Native searchable text") {
		t.Fatalf("PDF text stage: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(workspace, "preview.jpg")); err != nil {
		t.Fatal(err)
	}
	extractionParity(t, config, textPDF, result)

	scanPDF := pdfFixture(t, true)
	result, _ = runNativeExtractor(t, config, scanPDF)
	if result.Error != "" || result.Pages != 1 || !result.NeedsOCR || strings.TrimSpace(result.Body) != "" {
		t.Fatalf("PDF scan before OCR: %+v", result)
	}
	extractionParity(t, config, scanPDF, result)

	config.Phase = "ocr"
	result, workspace = runNativeExtractor(t, config, scanPDF)
	if result.Error != "" || result.Pages != 1 || result.NeedsOCR || !strings.Contains(strings.ToLower(result.Body), "invoice") {
		t.Fatalf("PDF scan after OCR: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(workspace, "preview.jpg")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OCR phase should reuse preview from text phase: %v", err)
	}
	extractionParity(t, config, scanPDF, result)
}

func pdfFixture(t *testing.T, scanned bool) []byte {
	t.Helper()
	var body, contents, resource string
	if !scanned {
		body = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`
		contents = `BT /F1 24 Tf 40 140 Td (Native searchable text) Tj ET`
		resource = `/Font << /F1 4 0 R >>`
	} else {
		// A raster-only page has no hidden text before actual Tesseract OCR.
		const width, height, scale = 760, 180, 5
		bitmap := image.NewGray(image.Rect(0, 0, width/scale, height/scale))
		for i := range bitmap.Pix {
			bitmap.Pix[i] = 255
		}
		drawer := font.Drawer{Dst: bitmap, Src: image.NewUniform(color.Black), Face: basicfont.Face7x13, Dot: fixed.P(8, 18)}
		drawer.DrawString("INVOICE NUMBER")
		pixels := make([]byte, width*height)
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				pixels[y*width+x] = bitmap.GrayAt(x/scale, y/scale).Y
			}
		}
		var compressed bytes.Buffer
		encoder := zlib.NewWriter(&compressed)
		if _, err := encoder.Write(pixels); err != nil {
			t.Fatal(err)
		}
		if err := encoder.Close(); err != nil {
			t.Fatal(err)
		}
		body = fmt.Sprintf(`<< /Type /XObject /Subtype /Image /Filter /FlateDecode /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d >>`+
			"\nstream\n%s\nendstream", width, height, compressed.Len(), compressed.String())
		contents = `q 350 0 0 83 20 70 cm /Image0 Do Q`
		resource = `/XObject << /Image0 4 0 R >>`
	}
	objects := []string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		`<< /Type /Pages /Count 1 /Kids [3 0 R] >>`,
		`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 230] /Resources << ` + resource + ` >> /Contents 5 0 R >>`,
		body,
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(contents), contents),
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	var offsets []int
	for i, object := range objects {
		offsets = append(offsets, pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return pdf.Bytes()
}
