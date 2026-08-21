import { useEffect, useState } from "react";

export interface CanvasSupport {
  /** Detection has run at least once (avoids a flash of the wrong view). */
  ready: boolean;
  /** WebGL is available and prefers-reduced-motion is not set. */
  supported: boolean;
  reducedMotion: boolean;
  documentVisible: boolean;
}

function detectWebgl(): boolean {
  try {
    const canvas = document.createElement("canvas");
    return !!(canvas.getContext("webgl2") || canvas.getContext("webgl"));
  } catch {
    return false;
  }
}

/**
 * Gates whether the R3F immersive canvas may mount. `prefers-reduced-motion`
 * and missing WebGL both fall back to the classic list view — the global CSS
 * kill-switch in styles.css does not cover a JS-driven useFrame render loop,
 * so this check is required, not redundant with it.
 */
export function useCanvasSupport(): CanvasSupport {
  const [state, setState] = useState<CanvasSupport>({
    ready: false, supported: false, reducedMotion: false, documentVisible: true,
  });

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const evaluate = () => {
      const reducedMotion = media.matches;
      const webgl = !reducedMotion && detectWebgl();
      setState({
        ready: true,
        supported: webgl,
        reducedMotion,
        documentVisible: document.visibilityState !== "hidden",
      });
    };
    evaluate();
    const onVisibility = () => {
      setState(prev => ({ ...prev, documentVisible: document.visibilityState !== "hidden" }));
    };
    media.addEventListener("change", evaluate);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      media.removeEventListener("change", evaluate);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return state;
}
