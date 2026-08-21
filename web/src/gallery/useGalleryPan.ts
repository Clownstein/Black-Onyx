import React, { useCallback, useEffect, useRef, useState } from "react";
import { useDrag } from "@use-gesture/react";
import { applyDragPanDelta, applyWheelPanDelta, GalleryOffset } from "./gallery_geometry";

export type { GalleryOffset };

/** Bumped when pan semantics change so a stale session offset can't reopen a broken view. */
const STORAGE_KEY = "blackonyx_gallery_offset_v4";
const DRAG_THRESHOLD = 10;

function loadPersistedOffset(): GalleryOffset {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { x: 0, y: 0 };
    const parsed = JSON.parse(raw);
    if (typeof parsed?.x === "number" && typeof parsed?.y === "number") return parsed;
  } catch {
    /* corrupt/unavailable storage — fall back to origin */
  }
  return { x: 0, y: 0 };
}

/**
 * Drag + wheel pan for the immersive canvas. Free 2D pan (no axis lock):
 * drag grabs the wall (content follows the pointer); wheel uses standard
 * scroll polarity (scroll down reveals lower tiles). The sphere wall maps
 * this offset onto an infinite lattice, so there is no hard stop.
 */
export function useGalleryPan() {
  const offsetRef = useRef<GalleryOffset>(loadPersistedOffset());
  const movedRef = useRef(false);
  const [root, setRoot] = useState<HTMLElement | null>(null);

  const onPointerDownCapture = useCallback((_event: React.PointerEvent) => {
    movedRef.current = false;
  }, []);

  const dragBind = useDrag(
    ({ delta: [dx, dy], last, tap, movement: [mx, my] }) => {
      if (Math.hypot(mx, my) > DRAG_THRESHOLD) movedRef.current = true;
      if (last) movedRef.current = !tap;
      // Grab the wall: content follows the pointer on both axes. Vertical was
      // previously +dy into a +panY map, which moved the shell opposite the drag.
      offsetRef.current = applyDragPanDelta(offsetRef.current, dx, dy);
    },
    { filterTaps: true, threshold: DRAG_THRESHOLD, pointer: { touch: true } },
  );

  useEffect(() => {
    if (!root) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      // Standard wheel polarity (Windows / non-natural): scroll down / right
      // moves content up / left — the previous subtract felt inverted.
      offsetRef.current = applyWheelPanDelta(offsetRef.current, event.deltaX, event.deltaY);
      movedRef.current = true;
    };
    root.addEventListener("wheel", onWheel, { passive: false });
    return () => root.removeEventListener("wheel", onWheel);
  }, [root]);

  useEffect(() => {
    const persist = () => {
      try {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(offsetRef.current));
      } catch {
        /* storage unavailable — pan simply won't restore */
      }
    };
    window.addEventListener("beforeunload", persist);
    return () => {
      persist();
      window.removeEventListener("beforeunload", persist);
    };
  }, []);

  const bind = useCallback(() => {
    const props = dragBind() as Record<string, unknown> & { ref?: React.Ref<HTMLElement | null> };
    const gestureRef = props.ref;
    return {
      ...props,
      ref: (node: HTMLElement | null) => {
        setRoot(node);
        if (typeof gestureRef === "function") gestureRef(node);
        else if (gestureRef && typeof gestureRef === "object") {
          (gestureRef as React.MutableRefObject<HTMLElement | null>).current = node;
        }
      },
    };
  }, [dragBind]);

  return { bind, offsetRef, movedRef, onPointerDownCapture };
}
