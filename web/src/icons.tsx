import React from "react";

type IconProps = { className?: string; title?: string };

function Svg({ children, className, title }: IconProps & { children: React.ReactNode }) {
  return (
    <svg className={className} width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden={title ? undefined : true} role={title ? "img" : undefined}>
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  );
}

export const Icons = {
  home: (p: IconProps) => <Svg {...p}><path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1v-9.5Z" /></Svg>,
  dashboard: (p: IconProps) => <Svg {...p}><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></Svg>,
  jobs: (p: IconProps) => <Svg {...p}><path d="M4 7h16v12H4z" /><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2" /><path d="M4 12h16" /></Svg>,
  ingest: (p: IconProps) => <Svg {...p}><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M5 19h14" /></Svg>,
  search: (p: IconProps) => <Svg {...p}><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></Svg>,
  image: (p: IconProps) => <Svg {...p}><rect x="3" y="5" width="18" height="14" rx="2" /><circle cx="9" cy="10" r="1.5" /><path d="m21 16-5-5-4 4-2-2-5 5" /></Svg>,
  collections: (p: IconProps) => <Svg {...p}><path d="M4 6h16v12H4z" /><path d="M8 6V4h8v2" /><path d="M8 10h8M8 14h5" /></Svg>,
  chat: (p: IconProps) => <Svg {...p}><path d="M4 5h16v11H8l-4 3V5Z" /></Svg>,
  ioc: (p: IconProps) => <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" /></Svg>,
  attack: (p: IconProps) => <Svg {...p}><path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z" /></Svg>,
  graph: (p: IconProps) => <Svg {...p}><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="7" r="2.5" /><circle cx="18" cy="17" r="2.5" /><path d="M8.3 11.2 15.7 8M8.3 12.8 15.7 16" /></Svg>,
  rules: (p: IconProps) => <Svg {...p}><path d="M8 4h10v16H8a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" /><path d="M10 8h6M10 12h6M10 16h4" /></Svg>,
  reports: (p: IconProps) => <Svg {...p}><path d="M6 3h9l3 3v15H6z" /><path d="M15 3v3h3" /><path d="M9 13h6M9 17h4" /></Svg>,
  cases: (p: IconProps) => <Svg {...p}><path d="M4 7h16v12H4z" /><path d="M9 7V5h6v2" /><path d="M9 12h6" /></Svg>,
  watchlists: (p: IconProps) => <Svg {...p}><path d="M12 4 4 7v5c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V7l-8-3Z" /></Svg>,
  feeds: (p: IconProps) => <Svg {...p}><path d="M5 19a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" /><path d="M5 6a13 13 0 0 1 13 13" /><path d="M5 11a8 8 0 0 1 8 8" /></Svg>,
  detections: (p: IconProps) => <Svg {...p}><path d="M12 3 4 6v6c0 5 3.4 7.6 8 9 4.6-1.4 8-4 8-9V6l-8-3Z" /><path d="m9 12 2 2 4-4" /></Svg>,
  playbooks: (p: IconProps) => <Svg {...p}><path d="M5 4h10l4 4v12H5z" /><path d="M15 4v4h4" /><path d="M9 13h6M9 17h4" /></Svg>,
  publishing: (p: IconProps) => <Svg {...p}><path d="M12 3v12" /><path d="m7 10 5-5 5 5" /><path d="M5 19h14" /></Svg>,
  decay: (p: IconProps) => <Svg {...p}><path d="M4 18c3-6 5-9 8-9s5 3 8 9" /><path d="M4 18h16" /></Svg>,
  bookmarks: (p: IconProps) => <Svg {...p}><path d="M7 4h10v16l-5-3-5 3V4Z" /></Svg>,
  system: (p: IconProps) => <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4" /></Svg>,
  analytics: (p: IconProps) => <Svg {...p}><path d="M4 19V5" /><path d="M4 19h16" /><path d="M8 15v-4M12 15V8M16 15v-7" /></Svg>,
  trends: (p: IconProps) => <Svg {...p}><path d="M3 17 9 11l4 4 8-9" /><path d="M14 6h7v7" /></Svg>,
  triage: (p: IconProps) => <Svg {...p}><path d="M4 6h16M4 12h10M4 18h7" /><circle cx="18" cy="12" r="3" /></Svg>,
  query: (p: IconProps) => <Svg {...p}><path d="M4 6h16M4 12h10M4 18h13" /><path d="m15 10 5 5" /></Svg>,
  assets: (p: IconProps) => <Svg {...p}><rect x="3" y="4" width="18" height="6" rx="1" /><rect x="3" y="14" width="8" height="6" rx="1" /><rect x="13" y="14" width="8" height="6" rx="1" /></Svg>,
  content: (p: IconProps) => <Svg {...p}><path d="M5 4h14v16H5z" /><path d="M9 8h6M9 12h6M9 16h4" /></Svg>,
  admin: (p: IconProps) => <Svg {...p}><circle cx="12" cy="8" r="3" /><path d="M5 20c1.5-3.5 4-5 7-5s5.5 1.5 7 5" /></Svg>,
  backup: (p: IconProps) => <Svg {...p}><path d="M4 7h12v12H4z" /><path d="M8 7V5h8v14h-2" /><path d="M10 12h4M12 10v4" /></Svg>,
  settings: (p: IconProps) => <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9c.3.6.9 1 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" /></Svg>,
  bell: (p: IconProps) => <Svg {...p}><path d="M6 9a6 6 0 1 1 12 0c0 7 3 7 3 7H3s3 0 3-7" /><path d="M10 19a2 2 0 0 0 4 0" /></Svg>,
  user: (p: IconProps) => <Svg {...p}><circle cx="12" cy="8" r="3.5" /><path d="M5 20c1.2-3.5 3.8-5 7-5s5.8 1.5 7 5" /></Svg>,
  logout: (p: IconProps) => <Svg {...p}><path d="M10 4H5v16h5" /><path d="M14 12H4" /><path d="m16 8 4 4-4 4" /></Svg>,
  theme: (p: IconProps) => <Svg {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></Svg>,
  menu: (p: IconProps) => <Svg {...p}><path d="M4 7h16M4 12h16M4 17h16" /></Svg>,
  chevronLeft: (p: IconProps) => <Svg {...p}><path d="m15 6-6 6 6 6" /></Svg>,
  chevronRight: (p: IconProps) => <Svg {...p}><path d="m9 6 6 6-6 6" /></Svg>,
  close: (p: IconProps) => <Svg {...p}><path d="M6 6l12 12M18 6 6 18" /></Svg>,
};

export type IconName = keyof typeof Icons;

export function NavIcon({ name, className }: { name: IconName | string; className?: string }) {
  const Comp = (Icons as Record<string, (p: IconProps) => React.ReactNode>)[name] || Icons.dashboard;
  return <>{Comp({ className: className || "nav-icon" })}</>;
}
