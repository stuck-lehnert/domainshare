"""Formats eligible for content search, shared by the catalog and parser."""

OFFICE_SUFFIXES = {'.docx', '.pptx', '.odt', '.odp'}
CONTENT_SUFFIXES = {'.pdf'} | OFFICE_SUFFIXES
IMAGE_SUFFIXES = {'.jpg', '.jpeg', '.png', '.tif', '.tiff', '.webp', '.bmp'}
