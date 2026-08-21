"""Image ingestion pipeline — PDF image extraction, perceptual hashing, image processing."""

from __future__ import annotations

import logging
import os
from typing import Any

from black_onyx.extraction.exif import extract_exif, get_coordinates
from black_onyx.models.enums import IMAGE_EXTENSIONS

logger = logging.getLogger(__name__)


def extract_images_from_pdf(pdf_path: str, output_dir: str) -> list[str]:
    """Extract embedded images from a PDF file.

    Uses PyMuPDF (imported as pymupdf, NOT fitz) to extract original image bytes.
    Handles CMYK to RGB conversion when needed.

    Args:
        pdf_path: Path to the PDF file.
        output_dir: Directory to save extracted images.

    Returns:
        List of paths to extracted image files.
    """
    try:
        import pymupdf
    except ImportError:
        logger.warning("PyMuPDF not installed; PDF image extraction unavailable. Install with: pip install pymupdf")
        return []

    os.makedirs(output_dir, exist_ok=True)
    image_paths: list[str] = []
    pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]

    try:
        doc = pymupdf.open(pdf_path)
        seen_xrefs: set[int] = set()

        for page_num in range(len(doc)):
            page = doc[page_num]
            for img in page.get_images(full=True):
                xref = img[0]
                if xref in seen_xrefs:
                    continue
                seen_xrefs.add(xref)

                try:
                    # Prefer extract_image for original bytes (faster, no re-encoding)
                    base = doc.extract_image(xref)
                    image_bytes = base["image"]
                    ext = base.get("ext", "png")

                    out_path = os.path.join(output_dir, f"{pdf_name}_p{page_num}_x{xref}.{ext}")
                    with open(out_path, "wb") as f:
                        f.write(image_bytes)
                    image_paths.append(out_path)

                except Exception as e:
                    # Fallback to Pixmap approach (handles CMYK conversion)
                    logger.debug(f"extract_image failed for xref {xref}, trying Pixmap: {e}")
                    try:
                        pix = pymupdf.Pixmap(doc, xref)
                        # CMYK to RGB conversion
                        if pix.n - pix.alpha > 3:
                            pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                        out_path = os.path.join(output_dir, f"{pdf_name}_p{page_num}_x{xref}.png")
                        pix.save(out_path)
                        image_paths.append(out_path)
                        del pix
                    except Exception as e2:
                        logger.warning(f"Failed to extract image xref {xref} from {pdf_path}: {e2}")

        doc.close()
    except Exception as e:
        logger.error(f"Failed to open PDF {pdf_path}: {e}")

    return image_paths


def compute_phash(image_path: str) -> str:
    """Compute perceptual hash of an image for deduplication.

    Uses imagehash.phash (DCT-based, most robust to resizing/compression).

    Args:
        image_path: Path to the image file.

    Returns:
        Hash string (e.g. "ffd7918181c9ffff"), or empty string on error.
    """
    try:
        import imagehash
        from PIL import Image
        img = Image.open(image_path)
        return str(imagehash.phash(img, hash_size=8))
    except ImportError:
        logger.warning("imagehash not installed; perceptual hashing unavailable. Install with: pip install ImageHash")
        return ""
    except Exception as e:
        logger.debug(f"Perceptual hash failed for {image_path}: {e}")
        return ""


def get_image_info(image_path: str) -> dict[str, Any]:
    """Get basic image information (width, height, format).

    Args:
        image_path: Path to the image file.

    Returns:
        Dict with width, height, format keys. Empty dict on error.
    """
    try:
        from PIL import Image
        img = Image.open(image_path)
        return {
            "width": img.width,
            "height": img.height,
            "format": img.format or os.path.splitext(image_path)[1].lstrip(".").upper(),
        }
    except ImportError:
        logger.warning("Pillow not installed; image info unavailable")
        return {}
    except Exception as e:
        logger.debug(f"Image info failed for {image_path}: {e}")
        return {}


def process_image(
    image_path: str,
    ocr_engine: Any = None,
    clip_model: Any = None,
) -> dict[str, Any]:
    """Process a single image through the full image ingestion pipeline.

    Extracts: EXIF/GPS metadata, OCR text, CLIP vision embedding,
    perceptual hash, and basic image info.

    Args:
        image_path: Path to the image file.
        ocr_engine: OCREngine instance (or None to skip OCR).
        clip_model: CLIPModel instance (or None to skip CLIP embedding).

    Returns:
        Dict with all extracted image data:
        - image_width, image_height, image_format
        - image_hash (perceptual hash string)
        - exif_data, gps_latitude, gps_longitude, camera_make, camera_model, capture_time
        - ocr_text
        - clip_vector (list[float])
    """
    result: dict[str, Any] = {}

    # Basic image info
    info = get_image_info(image_path)
    result["image_width"] = info.get("width")
    result["image_height"] = info.get("height")
    result["image_format"] = info.get("format")

    # Perceptual hash for dedup
    result["image_hash"] = compute_phash(image_path)

    # EXIF / GPS
    exif = extract_exif(image_path)
    result["exif_data"] = exif.get("all_exif")
    result["camera_make"] = exif.get("camera_make")
    result["camera_model"] = exif.get("camera_model")
    result["capture_time"] = exif.get("capture_time")
    lat, lon = get_coordinates(exif)
    result["gps_latitude"] = lat
    result["gps_longitude"] = lon

    # OCR text
    ocr_text = ""
    if ocr_engine is not None:
        ocr_text = ocr_engine.extract_text(image_path)
    result["ocr_text"] = ocr_text if ocr_text else None

    # CLIP embedding
    clip_vector: list[float] = []
    if clip_model is not None:
        clip_vector = clip_model.embed_image(image_path)
    result["clip_vector"] = clip_vector if clip_vector else None

    return result


def is_image_file(filepath: str) -> bool:
    """Check if a file is an image based on its extension.

    Args:
        filepath: Path to the file.

    Returns:
        True if the file extension is in IMAGE_EXTENSIONS.
    """
    ext = os.path.splitext(filepath)[1].lower()
    return ext in IMAGE_EXTENSIONS
