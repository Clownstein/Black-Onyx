type BrandLogoProps = {
  variant?: "mark" | "lockup" | "hero";
  className?: string;
};

/** Serves the repository-root transparent lockup via Vite as `/logo.png`. */
export function BrandLogo({ variant = "lockup", className = "" }: BrandLogoProps) {
  const classes = ["brand-logo", `brand-logo-${variant}`, className].filter(Boolean).join(" ");
  // Cache-bust when the transparent asset is replaced without a filename change.
  return <img className={classes} src="/logo.png?v=2" alt="Black Onyx" decoding="async" />;
}
