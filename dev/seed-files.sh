#!/usr/bin/env bash
set -Eeuo pipefail

seed_mb=${DEV_SEED_MB:-8}

mkdir -p \
  /data/groups/data/Finance/Reports \
  /data/groups/data/Engineering/Designs \
  /data/groups/data/Projects/Planning \
  /data/private/alice \
  /data/private/bob \
  /data/private/carol \
  /data/private/dave \
  /data/private/eve \
  /data/fslogix/alice_S-1-5-21-111-222-333-1101 \
  /data/fslogix/carol_S-1-5-21-111-222-333-1103

printf 'Quarter,Forecast\nQ1,120000\nQ2,135000\n' > /data/groups/data/Finance/Reports/forecast.csv
printf '# Architecture\n\nPreview design notes.\n' > /data/groups/data/Engineering/Designs/architecture.md
printf 'Milestone,Owner\nDiscovery,Eve\nDelivery,Carol\n' > /data/groups/data/Projects/Planning/roadmap.csv
printf 'Alice private preview data. ALICEPRIVATE742\n' > /data/private/alice/readme.txt
printf 'Bob private preview data. BOBPRIVATE742\n' > /data/private/bob/readme.txt
printf 'Carol private preview data.\n' > /data/private/carol/readme.txt
printf 'Dummy FSLogix profile for Alice.\n' > /data/fslogix/alice_S-1-5-21-111-222-333-1101/profile.vhdx
printf 'Dummy FSLogix profile for Carol.\n' > /data/fslogix/carol_S-1-5-21-111-222-333-1103/profile.vhdx

dd if=/dev/zero of=/data/groups/data/Finance/Reports/history.bin bs=1M count="$seed_mb" status=none
dd if=/dev/zero of=/data/groups/data/Engineering/Designs/models.bin bs=1M count="$seed_mb" status=none
dd if=/dev/zero of=/data/fslogix/alice_S-1-5-21-111-222-333-1101/profile-data.bin bs=1M count="$seed_mb" status=none


printf '[preview-seed] Seeded group, private, and FSLogix data.\n'

# Native text, image-only scan and Office fixture for the document portal.
python3 - <<'PYDOCUMENTS'
from pathlib import Path
import zipfile
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
root=Path('/data/groups/data/Finance/Reports')
native=canvas.Canvas(str(root/'digital-invoice.pdf'))
native.drawString(72,760,'Digital invoice NATIVEINVOICE742')
native.showPage()
native.drawString(72,760,'Digital invoice page 2')
native.showPage()
native.drawString(72,760,'Digital invoice page 3')
native.save()
image=Image.new('RGB',(1654,2339),'white')
font=next(Path('/usr/share/fonts').rglob('NimbusSans-Regular.otf'))
draw=ImageDraw.Draw(image)
draw.text((120,200),'INVOICE SCAN\nCustomer reference SCANNEDUNIQUE742\nInvoice total 1500 EUR\nPayment due 30 October 2026',fill='black',font=ImageFont.truetype(str(font),44),spacing=40)
image.save(root/'scanned-invoice.pdf','PDF',resolution=150)

# Large portrait/landscape images and a small image for responsive preview checks.
# Generate them locally so the preview needs no external downloads or image assets.
def preview_image(path, width, height):
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new('RGB', (width, height), '#dceaf2')
    draw = ImageDraw.Draw(image)
    unit = min(width, height)
    sun = unit // 9
    center = (width * 3 // 4, height // 4)
    draw.ellipse((center[0] - sun, center[1] - sun,
                  center[0] + sun, center[1] + sun), fill='#e7bb57')
    draw.polygon([(0, height * 3 // 4), (width // 3, height // 3),
                  (width * 3 // 4, height * 4 // 5), (width, height // 2),
                  (width, height), (0, height)], fill='#7e9a82')
    draw.polygon([(0, height * 9 // 10), (width // 2, height * 3 // 5),
                  (width, height * 4 // 5), (width, height), (0, height)], fill='#59796a')
    margin = unit // 20
    label_font = ImageFont.truetype(str(font), max(12, unit // 24))
    draw.text((margin, margin), f'{width} × {height} px', fill='#304a60', font=label_font)
    draw.text((margin, height - margin - unit // 20), 'IMAGEPREVIEW742', fill='white', font=label_font)
    draw.rectangle((0, 0, width - 1, height - 1), outline='#304a60', width=max(2, unit // 100))
    image.save(path)

photos = Path('/data/groups/data/Finance/Photos')
preview_image(photos/'portrait-4000x6000.jpg', 4000, 6000)
preview_image(photos/'landscape-6000x4000.png', 6000, 4000)
preview_image(photos/'small-320x240.png', 320, 240)
preview_image(Path('/data/private/alice/private-portrait.jpg'), 2400, 3600)

for folder in (root,Path('/data/private/alice')):
    for name in ('Thumbs.db','THUMBS.DB','~$Locked.docx','~$Locked.pptx'):
        (folder/name).write_text('IGNOREDARTIFACT742')
(root/'index-excluded.txt').write_text('TEXTONLY742 should never be content-indexed')
for suffix,entry in [('xlsx','xl/sharedStrings.xml'),('ods','content.xml')]:
    with zipfile.ZipFile(root/('index-excluded.'+suffix),'w') as spreadsheet:
        spreadsheet.writestr(entry,'<document><t>SPREADSHEETONLY742</t></document>')
for name,marker in [('alice','ALICEPRIVATE742'),('bob','BOBPRIVATE742')]:
    with zipfile.ZipFile(Path('/data/private')/name/'readme.docx','w') as private:
        private.writestr('word/document.xml','<document><body><p><t>'+marker+'</t></p></body></document>')
for suffix,entry,marker in [('pptx','ppt/slides/slide1.xml','POWERPOINTONLY742'),('odt','content.xml','ODTONLY742'),('odp','content.xml','ODPONLY742')]:
    with zipfile.ZipFile(root/('office-notes.'+suffix),'w') as office:
        office.writestr(entry,'<document><body><p><t>'+marker+'</t></p></body></document>')
with zipfile.ZipFile(root/'office-notes.docx','w') as office:
    office.writestr('word/document.xml','<document><body><p><t>Office document OFFICETEXT742</t></p></body></document>')
PYDOCUMENTS

# Seed the old state layout to exercise the one-time migration on startup.
python3 - <<'PYSEED'
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path

conn = sqlite3.connect('/state/shares.db')
conn.execute("CREATE TABLE shares (objectGUID TEXT PRIMARY KEY, samAccountName TEXT NOT NULL, shareName TEXT NOT NULL, path TEXT NOT NULL, createdAt TEXT NOT NULL, lastSeenAt TEXT NOT NULL, isActive INTEGER NOT NULL DEFAULT 1)")
manifest = {}
for name in ('Finance', 'Engineering', 'Projects'):
    guid = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'preview.FS_' + name))
    original = Path('/data/groups/data') / name
    legacy = Path('/data/groups') / guid
    for entry in original.rglob('*'):
        if entry.is_file():
            relative = str(Path(name) / entry.relative_to(original))
            manifest[relative] = {'sha256': hashlib.sha256(entry.read_bytes()).hexdigest(), 'inode': entry.stat().st_ino}
    os.rename(original, legacy)
    conn.execute("INSERT INTO shares VALUES(?,?,?,?,?,?,1)", (guid, 'FS_' + name, name, str(legacy), '2026-01-01', '2026-01-01'))
conn.commit()
Path('/state/preview-legacy-manifest.json').write_text(json.dumps(manifest))
PYSEED
