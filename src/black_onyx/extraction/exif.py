"""EXIF and GPS metadata extraction from images using Pillow."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def dms_to_decimal(dms: Any, ref: str) -> float:
    """Convert GPS DMS (degrees, minutes, seconds) rational tuples to decimal degrees.

    Args:
        dms: Tuple of (numerator, denominator) rational values for degrees, minutes, seconds.
        ref: Reference direction ('N', 'S', 'E', 'W').

    Returns:
        Decimal degrees as a float. Negative for S/W.
    """
    try:
        degrees = float(dms[0][0]) / float(dms[0][1]) if isinstance(dms[0], (tuple, list)) else float(dms[0])
        minutes = float(dms[1][0]) / float(dms[1][1]) if isinstance(dms[1], (tuple, list)) else float(dms[1])
        seconds = float(dms[2][0]) / float(dms[2][1]) if isinstance(dms[2], (tuple, list)) else float(dms[2])
        decimal = degrees + minutes / 60.0 + seconds / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except (IndexError, TypeError, ZeroDivisionError) as e:
        logger.warning(f"GPS DMS conversion failed: {e}")
        return 0.0


def extract_exif(image_path: str) -> dict[str, Any]:
    """Extract EXIF metadata from an image file.

    Uses Pillow's modern getexif() API. Extracts camera info, capture time,
    and GPS coordinates (converted to decimal degrees).

    Args:
        image_path: Path to the image file.

    Returns:
        Dict with keys: camera_make, camera_model, capture_time,
        gps_latitude, gps_longitude, all_exif (raw dict).
        Empty dict if no EXIF data or on error.
    """
    try:
        from PIL import Image
        from PIL.ExifTags import GPSTAGS, IFD, TAGS

        img = Image.open(image_path)
        exif = img.getexif()

        if not exif:
            return {}

        result: dict[str, Any] = {"all_exif": {}}

        # Extract standard EXIF tags
        for tag_id, value in exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            result["all_exif"][tag_name] = str(value)

            # Map common tags to named fields
            if tag_name == "Make":
                result["camera_make"] = str(value).strip()
            elif tag_name == "Model":
                result["camera_model"] = str(value).strip()
            elif tag_name in ("DateTime", "DateTimeOriginal"):
                result["capture_time"] = str(value)

        # Extract GPS data
        gps_ifd = exif.get_ifd(IFD.GPSInfo)
        if gps_ifd:
            gps_data: dict[str, Any] = {}
            for gps_tag_id, value in gps_ifd.items():
                gps_name = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                gps_data[gps_name] = value

            result["all_exif"]["GPSInfo"] = {k: str(v) for k, v in gps_data.items()}

            # Convert GPS coordinates to decimal
            lat = None
            lon = None
            if "GPSLatitude" in gps_data:
                lat_ref = gps_data.get("GPSLatitudeRef", "N")
                lat = dms_to_decimal(gps_data["GPSLatitude"], lat_ref)
                result["gps_latitude"] = lat
            if "GPSLongitude" in gps_data:
                lon_ref = gps_data.get("GPSLongitudeRef", "E")
                lon = dms_to_decimal(gps_data["GPSLongitude"], lon_ref)
                result["gps_longitude"] = lon

        return result

    except ImportError:
        logger.warning("Pillow not installed; EXIF extraction unavailable. Install with: pip install Pillow")
        return {}
    except Exception as e:
        logger.debug(f"EXIF extraction failed for {image_path}: {e}")
        return {}


def get_coordinates(exif_data: dict[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Extract GPS coordinates from an EXIF data dict.

    Args:
        exif_data: Dict from extract_exif().

    Returns:
        Tuple of (latitude, longitude) or (None, None) if not available.
    """
    lat = exif_data.get("gps_latitude")
    lon = exif_data.get("gps_longitude")
    return lat, lon
