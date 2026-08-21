import * as THREE from "three";

/** Concave sphere radius — centre at z = +R; wall through origin. */
export const GALLERY_RADIUS = 14;

/**
 * Inward sphere (camera inside). Arc-length → (θ, φ), then:
 *   x = R·sinθ·cosφ
 *   y = R·sinφ
 *   z = R - R·cosθ·cosφ
 *   rotation (φ, -θ, 0) — yaw/pitch only, no roll.
 */
export function poseOnConcaveSphere(
  xArc: number,
  yArc: number,
  radius = GALLERY_RADIUS,
): { position: THREE.Vector3; rotation: THREE.Euler } {
  const theta = xArc / radius;
  const phi = yArc / radius;
  const cosPhi = Math.cos(phi);
  const x = radius * Math.sin(theta) * cosPhi;
  const y = radius * Math.sin(phi);
  const z = radius - radius * Math.cos(theta) * cosPhi;
  return {
    position: new THREE.Vector3(x, y, z),
    rotation: new THREE.Euler(phi, -theta, 0, "XYZ"),
  };
}

export interface GalleryOffset {
  x: number;
  y: number;
}

/** Grab polarity: content follows the pointer (invert vertical delta). */
export function applyDragPanDelta(offset: GalleryOffset, dx: number, dy: number): GalleryOffset {
  return { x: offset.x + dx, y: offset.y - dy };
}

/** Standard wheel polarity (Windows / non-natural): scroll down / right adds. */
export function applyWheelPanDelta(
  offset: GalleryOffset,
  deltaX: number,
  deltaY: number,
): GalleryOffset {
  return { x: offset.x + deltaX, y: offset.y + deltaY };
}
