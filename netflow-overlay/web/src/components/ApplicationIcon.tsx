import { siYoutube, siNetflix, siBilibili, siSpotify, siGithub, siTelegram, siDiscord, siSteam, siDeepseek, siGitlab, siDocker, siPypi, siNpm } from "simple-icons";

type BrandIcon = { path: string; hex: string; title: string };
const brands: Record<string, BrandIcon> = {
  "youtube": siYoutube, "netflix": siNetflix, "哔哩哔哩": siBilibili,
  "spotify": siSpotify, "github": siGithub, "telegram": siTelegram,
  "discord": siDiscord, "steam": siSteam, "deepseek": siDeepseek,
  "gitlab": siGitlab, "docker hub": siDocker, "pypi": siPypi, "npm": siNpm,
};

/** Lookup is by the exact application label, never by an arbitrary domain. */
export function ApplicationIcon({ name }: { name: string }) {
  const brand = brands[name.trim().toLowerCase()];
  return <span className="application-icon" aria-hidden="true" style={brand ? {color: `#${brand.hex}`} : undefined}>
    {brand ? <svg viewBox="0 0 24 24" width="21" height="21" fill="currentColor" focusable="false"><path d={brand.path} /></svg>
      : <svg viewBox="0 0 24 24" width="21" height="21" fill="none" stroke="currentColor" strokeWidth="1.7" focusable="false"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>}
  </span>;
}
