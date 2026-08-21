import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " G";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + " M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + " k";
  return String(n);
}

export function formatRate(eps: number): string {
  return formatNumber(eps) + " /s";
}

export function formatBps(bps: number): string {
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kbps";
  return Math.round(bps) + " bps";
}

export function formatPct(pct: number): string {
  return pct + "%";
}

export function shortTs(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  return `${h}:${m}`;
}