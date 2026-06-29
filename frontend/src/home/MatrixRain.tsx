import { useEffect, useRef } from "react";

/**
 * Matrix "digital rain" backdrop for the engagements dashboard header.
 *
 * A self-contained canvas — no deps. Columns of glyphs fall in the app's accent
 * green (read live from the --accent-rgb CSS var so it tracks the theme), with a
 * bright leading character and a fading trail. It's purely decorative: the
 * canvas is aria-hidden and pointer-events-none, sits behind the header content,
 * and meant to be wrapped at a low opacity by the caller.
 *
 * Respectful of resources:
 *   - honours prefers-reduced-motion (renders one static frame, no loop)
 *   - pauses while the document/tab is hidden
 *   - caps the frame rate and scales for devicePixelRatio
 *   - cleans up its RAF, observers, and listeners on unmount
 */
export default function MatrixRain({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas0 = canvasRef.current;
    if (!canvas0) return;
    const canvas = canvas0; // non-null capture so the closures below keep the narrowing
    const ctx0 = canvas.getContext("2d");
    if (!ctx0) return;
    const ctx = ctx0; // non-null capture so the closures below keep the narrowing

    // Katakana + digits + a few sigils — the classic rain alphabet.
    const GLYPHS =
      "アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズヅブプ0123456789:.=*+-<>";
    const FONT = 15; // px cell size
    const reduceMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;

    let cols = 0;
    let drops: number[] = [];
    let cssW = 0;
    let cssH = 0;

    function accent(alpha: number): string {
      const rgb =
        getComputedStyle(document.documentElement)
          .getPropertyValue("--accent-rgb")
          .trim() || "57 217 138";
      return `rgba(${rgb.replace(/\s+/g, ",")}, ${alpha})`;
    }

    function resize() {
      const parent = canvas.parentElement;
      if (!parent) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      cssW = parent.clientWidth;
      cssH = parent.clientHeight;
      canvas.width = Math.max(1, Math.floor(cssW * dpr));
      canvas.height = Math.max(1, Math.floor(cssH * dpr));
      canvas.style.width = `${cssW}px`;
      canvas.style.height = `${cssH}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = `${FONT}px ui-monospace, "SF Mono", Menlo, monospace`;
      ctx.textBaseline = "top";
      const next = Math.ceil(cssW / FONT);
      // Preserve existing column positions on resize; seed new ones up high.
      drops = Array.from({ length: next }, (_, i) =>
        i < cols ? drops[i] : Math.floor((Math.random() * -cssH) / FONT),
      );
      cols = next;
    }

    function draw() {
      // Translucent fill paints the fading trail over the previous frame.
      ctx.fillStyle = "rgba(10, 14, 21, 0.10)";
      ctx.fillRect(0, 0, cssW, cssH);

      for (let i = 0; i < cols; i++) {
        const x = i * FONT;
        const y = drops[i] * FONT;
        const ch = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];

        // Bright leading glyph, dimmer body for the trail.
        ctx.fillStyle = accent(0.95);
        ctx.fillText(ch, x, y);
        ctx.fillStyle = accent(0.35);
        ctx.fillText(
          GLYPHS[Math.floor(Math.random() * GLYPHS.length)],
          x,
          y - FONT,
        );

        // Reset the column to the top at random once it falls off-screen,
        // so the streams desynchronise instead of marching in lockstep.
        if (y > cssH && Math.random() > 0.975) drops[i] = 0;
        else drops[i]++;
      }
    }

    resize();

    if (reduceMotion) {
      // One static frame — no animation loop.
      ctx.fillStyle = "rgba(10, 14, 21, 1)";
      ctx.fillRect(0, 0, cssW, cssH);
      draw();
      return;
    }

    let raf = 0;
    let last = 0;
    const FRAME_MS = 1000 / 20; // ~20fps is plenty for rain
    const loop = (t: number) => {
      raf = requestAnimationFrame(loop);
      if (document.hidden) return;
      if (t - last < FRAME_MS) return;
      last = t;
      draw();
    };
    raf = requestAnimationFrame(loop);

    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={className}
      aria-hidden
      style={{ pointerEvents: "none" }}
    />
  );
}
