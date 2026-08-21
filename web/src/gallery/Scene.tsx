import React, { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import { GalleryTile } from "./types";
import { createTileTexture } from "./tile_texture";
import { useGalleryPan, GalleryOffset } from "./useGalleryPan";
import { GALLERY_RADIUS, poseOnConcaveSphere } from "./gallery_geometry";

/** Larger plates, tight gutters — reads denser like the reference wall. */
const TILE_WIDTH = 2.72;
const TILE_HEIGHT = 1.92;
/** Arc-length cell pitch on the sphere (only a slim gutter beyond the mesh). */
const CELL_W = 2.82;
const CELL_H = 2.0;
/**
 * Concave sphere radius. Sphere centre sits at z = +R (camera side);
 * the wall passes through the origin. See new_ui_template.md.
 */
const RADIUS = GALLERY_RADIUS;
/** Camera on +Z, inside the sphere (must stay < 2R). */
const CAM_DIST = 5.25;
const FOV = 55;
/** How many pool cells cover the viewport (odd keeps a true centre cell). */
const POOL_COLS = 13;
const POOL_ROWS = 9;
const PAN_SCALE = 0.014;
const DAMP = 8;
const MIN_COLUMNS = 4;
const MAX_COLUMNS = 7;

function layoutColumns(tileCount: number): number {
  const target = Math.ceil(Math.sqrt(Math.max(1, tileCount) * 2.2));
  return Math.min(MAX_COLUMNS, Math.max(MIN_COLUMNS, target));
}

function positiveMod(value: number, modulo: number): number {
  return ((value % modulo) + modulo) % modulo;
}

/** Map infinite lattice coords onto the repeating tile block. */
function tileIndexAt(col: number, row: number, blockCols: number, blockRows: number, tileCount: number): number {
  const c = positiveMod(col, blockCols);
  const r = positiveMod(row, blockRows);
  const idx = r * blockCols + c;
  return positiveMod(idx, tileCount);
}

function AdaptiveResolution() {
  const { gl } = useThree();
  const frames = useRef(0);
  const last = useRef(performance.now());
  useFrame(() => {
    frames.current += 1;
    const now = performance.now();
    if (now - last.current < 1000) return;
    const fps = (frames.current * 1000) / (now - last.current);
    frames.current = 0;
    last.current = now;
    const next = fps < 40 ? 1 : Math.min(typeof window !== "undefined" ? window.devicePixelRatio : 1, 1.75);
    if (gl.getPixelRatio() !== next) gl.setPixelRatio(next);
  });
  return null;
}

interface PoolProps {
  tiles: GalleryTile[];
  offsetRef: React.MutableRefObject<GalleryOffset>;
  movedRef: React.MutableRefObject<boolean>;
  reducedMotion: boolean;
  onNavigate: (tile: GalleryTile) => void;
  focusIndex: number | null;
}

function InfiniteSphereWall({ tiles, offsetRef, movedRef, reducedMotion, onNavigate, focusIndex }: PoolProps) {
  const blockCols = useMemo(() => layoutColumns(tiles.length), [tiles.length]);
  const blockRows = useMemo(() => Math.max(1, Math.ceil(tiles.length / blockCols)), [tiles.length, blockCols]);
  const poolSize = POOL_COLS * POOL_ROWS;

  const textureKey = useMemo(
    () => tiles.map(tile => {
      const metrics = tile.metrics ? JSON.stringify(tile.metrics) : "";
      const spark = tile.sparkline?.length ? tile.sparkline.join(",") : "";
      return `${tile.id}|${tile.title}|${tile.subtitle}|${tile.badge ?? ""}|${tile.glyph ?? ""}|${metrics}|${spark}`;
    }).join(";;"),
    [tiles],
  );

  const textures = useMemo(
    () => tiles.map(tile => createTileTexture(tile)),
    // textureKey captures every field that affects the raster
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [textureKey],
  );

  useEffect(() => () => { textures.forEach(texture => texture.dispose()); }, [textures]);

  const meshRefs = useRef<Array<THREE.Mesh | null>>(Array(poolSize).fill(null));
  const materialRefs = useRef<Array<THREE.MeshBasicMaterial | null>>(Array(poolSize).fill(null));
  const slotTileIndex = useRef<number[]>(Array(poolSize).fill(0));
  const pan = useRef({ x: 0, y: 0 });
  const halfCols = (POOL_COLS - 1) / 2;
  const halfRows = (POOL_ROWS - 1) / 2;

  useEffect(() => {
    if (focusIndex === null || focusIndex < 0 || focusIndex >= tiles.length) return;
    const col = focusIndex % blockCols;
    const row = Math.floor(focusIndex / blockCols);
    // Centre that lattice cell on the optical axis (xArc = yArc = 0).
    offsetRef.current = {
      x: (-col * CELL_W) / PAN_SCALE,
      y: (row * CELL_H) / PAN_SCALE,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusIndex, blockCols]);

  useFrame((_, delta) => {
    const dt = Math.min(delta, 0.05);
    const targetX = offsetRef.current.x * PAN_SCALE;
    const targetY = offsetRef.current.y * PAN_SCALE;
    if (reducedMotion) {
      pan.current.x = targetX;
      pan.current.y = targetY;
    } else {
      pan.current.x = THREE.MathUtils.damp(pan.current.x, targetX, DAMP, dt);
      pan.current.y = THREE.MathUtils.damp(pan.current.y, targetY, DAMP, dt);
    }

    // Grab polarity: offset grows with drag, and is added into arc space so
    // content follows the pointer. Wheel adds delta in useGalleryPan.
    const panX = pan.current.x;
    const panY = pan.current.y;
    const centerCol = Math.round(-panX / CELL_W);
    const centerRow = Math.round(panY / CELL_H);

    for (let i = 0; i < poolSize; i++) {
      const mesh = meshRefs.current[i];
      const material = materialRefs.current[i];
      if (!mesh || !material) continue;

      const localCol = (i % POOL_COLS) - halfCols;
      const localRow = Math.floor(i / POOL_COLS) - halfRows;
      const col = centerCol + localCol;
      const row = centerRow + localRow;

      const xArc = col * CELL_W + panX;
      const yArc = -row * CELL_H + panY;
      const { position, rotation } = poseOnConcaveSphere(xArc, yArc);
      mesh.position.copy(position);
      mesh.rotation.copy(rotation);

      const tileIdx = tileIndexAt(col, row, blockCols, blockRows, tiles.length);
      slotTileIndex.current[i] = tileIdx;
      const nextMap = textures[tileIdx];
      if (material.map !== nextMap) {
        material.map = nextMap;
        material.needsUpdate = true;
      }

      // Hide cells that curl too far behind the camera / past the limb.
      const visible = Math.abs(xArc / RADIUS) < 1.35 && Math.abs(yArc / RADIUS) < 1.1 && position.z < CAM_DIST - 0.35;
      mesh.visible = visible;
    }
  });

  return (
    <group>
      {Array.from({ length: poolSize }, (_, index) => (
        <mesh
          key={index}
          ref={node => { meshRefs.current[index] = node; }}
          onClick={event => {
            event.stopPropagation();
            if (movedRef.current) return;
            const tile = tiles[slotTileIndex.current[index]];
            if (tile) onNavigate(tile);
          }}
          onPointerOver={event => {
            event.stopPropagation();
            const mesh = meshRefs.current[index];
            if (mesh) mesh.scale.setScalar(1.04);
          }}
          onPointerOut={event => {
            event.stopPropagation();
            const mesh = meshRefs.current[index];
            if (mesh) mesh.scale.setScalar(1);
          }}
        >
          <planeGeometry args={[TILE_WIDTH, TILE_HEIGHT]} />
          <meshBasicMaterial
            ref={node => { materialRefs.current[index] = node; }}
            toneMapped={false}
            transparent
          />
        </mesh>
      ))}
    </group>
  );
}

function AimCamera() {
  const { camera } = useThree();
  useEffect(() => {
    camera.lookAt(0, 0, 0);
  }, [camera]);
  return null;
}

/**
 * Fires once the renderer has actually drawn a frame. Until then the scene
 * graph exists but nothing is on screen and there is no geometry to raycast
 * against, so a pointer press lands on empty canvas. Drives the fade-in and
 * the `data-scene-ready` hook that lets tests wait for a genuinely
 * interactive canvas instead of guessing with a sleep.
 */
function FirstFrameSignal({ onReady }: { onReady: () => void }) {
  const fired = useRef(false);
  useFrame(() => {
    if (fired.current) return;
    fired.current = true;
    onReady();
  });
  return null;
}

export interface GallerySceneProps {
  tiles: GalleryTile[];
  reducedMotion: boolean;
  documentVisible: boolean;
  onNavigate: (tile: GalleryTile) => void;
  /** Index (within `tiles`) to ease toward, or null. */
  focusIndex: number | null;
}

export function GalleryScene({ tiles, reducedMotion, documentVisible, onNavigate, focusIndex }: GallerySceneProps) {
  const { bind, offsetRef, movedRef, onPointerDownCapture } = useGalleryPan();
  const [ready, setReady] = useState(false);

  if (!tiles.length) return null;

  return (
    <div
      className="gallery-canvas-root"
      data-scene-ready={ready ? "true" : "false"}
      onPointerDownCapture={onPointerDownCapture}
      {...(bind() as unknown as React.HTMLAttributes<HTMLDivElement>)}
    >
      <Canvas
        frameloop={!documentVisible ? "never" : "always"}
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true }}
        camera={{ position: [0, 0.2, CAM_DIST], fov: FOV, near: 0.1, far: RADIUS * 3 }}
        onCreated={({ gl }) => {
          // Keep the WebGL buffer clear so BlackOnyxBackground shows through
          // gaps between tiles instead of a solid black clear colour.
          gl.setClearColor(0x000000, 0);
        }}
      >
        <AimCamera />
        <FirstFrameSignal onReady={() => setReady(true)} />
        <AdaptiveResolution />
        {/* Fog matches brand deep black; kept soft so the photographic ground
            remains visible behind the rim rather than washing to void. */}
        <fog attach="fog" args={["#0B0B0E", CAM_DIST + 1.8, CAM_DIST + RADIUS * 1.05]} />
        <InfiniteSphereWall
          tiles={tiles}
          offsetRef={offsetRef}
          movedRef={movedRef}
          reducedMotion={reducedMotion}
          onNavigate={onNavigate}
          focusIndex={focusIndex}
        />
      </Canvas>
    </div>
  );
}
