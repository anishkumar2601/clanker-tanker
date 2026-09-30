import React from 'react'

const paths = {
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  alert: 'M12 3 2.5 20h19L12 3Zm0 6v5m0 3h.01',
  down: 'M12 4v16m-6-6 6 6 6-6',
  upRight: 'M7 17 17 7M7 7h10v10',
  bot: 'M12 8V4m-4 4h8m-9 4h.01m9 0h.01M8 17h8a3 3 0 0 0 3-3v-2a3 3 0 0 0-3-3H8a3 3 0 0 0-3 3v2a3 3 0 0 0 3 3Zm2 0v3m4-3v3',
  check: 'm4 12 5 5L20 6',
  chevron: 'm9 18 6-6-6-6',
  help: 'M9.5 9a2.7 2.7 0 1 1 4.9 1.6c-1.2 1.4-2.4 1.5-2.4 3.1m.01 3.1h.01',
  code: 'm8 9-4 3 4 3m8-6 4 3-4 3m-3-10-2 14',
  database: 'M4 6c0-2 16-2 16 0v12c0 2-16 2-16 0V6Zm0 6c0 2 16 2 16 0M4 6c0 2 16 2 16 0',
  archive: 'M4 7h16M6 7v12h12V7M8 4h8v3H8m1 5h6',
  file: 'M6 3h8l4 4v14H6V3Zm8 0v5h4',
  folder: 'M3 6h7l2 2h9v10H3V6Z',
  gauge: 'M4 18a8 8 0 1 1 16 0M12 14l3-3',
  branch: 'M6 3v12a3 3 0 1 0 3 3m6-15v6a3 3 0 1 1-3 3H9',
  lock: 'M6 10h12v10H6V10Zm3 0V7a3 3 0 0 1 6 0v3',
  menu: 'M4 6h16M4 12h16M4 18h16',
  network: 'M12 3v5m0 8v5M5 12h14M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z',
  refresh: 'M20 11a8 8 0 0 0-14.9-3M4 5v4h4m-4 2a8 8 0 0 0 14.9 3M20 19v-4h-4',
  scan: 'M4 7V4h3m10 0h3v3m0 10v3h-3M7 20H4v-3m3-5h10m-5-5v10',
  server: 'M4 5h16v5H4V5Zm0 9h16v5H4v-5Zm3-6h.01m0 9h.01',
  shield: 'M12 3 20 6v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3Z',
  shieldCheck: 'M12 3 20 6v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3Zm-4 9 3 3 5-6',
  sparkles: 'm12 3 1.3 4.2L17 9l-3.7 1.8L12 15l-1.3-4.2L7 9l3.7-1.8L12 3Zm7 10 .6 2.1L22 16l-2.4.9L19 19l-.6-2.1L16 16l2.4-.9L19 13Z',
  terminal: 'm5 7 4 5-4 5m6 0h8',
  test: 'M9 3h6m-5 0v6l-4 8a2 2 0 0 0 2 3h8a2 2 0 0 0 2-3l-4-8V3m-5 9h8',
  upload: 'M12 16V4m0 0L7 9m5-5 5 5M5 20h14',
  x: 'm6 6 12 12M18 6 6 18',
  zap: 'm13 2-9 12h7l-1 8 9-12h-7l1-8Z',
}

function makeIcon(name) {
  return function Icon({ size = 18, strokeWidth = 1.8, className = '' }) {
    return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true"><path d={paths[name]} /></svg>
  }
}

export const Activity = makeIcon('activity')
export const AlertTriangle = makeIcon('alert')
export const ArrowDown = makeIcon('down')
export const ArrowUpRight = makeIcon('upRight')
export const Bot = makeIcon('bot')
export const Check = makeIcon('check')
export const ChevronRight = makeIcon('chevron')
export const CircleHelp = makeIcon('help')
export const Code2 = makeIcon('code')
export const Database = makeIcon('database')
export const FileArchive = makeIcon('archive')
export const FileCode2 = makeIcon('file')
export const FolderGit2 = makeIcon('folder')
export const Gauge = makeIcon('gauge')
export const GitBranch = makeIcon('branch')
export const KeyRound = makeIcon('lock')
export const Layers3 = makeIcon('network')
export const LockKeyhole = makeIcon('lock')
export const Menu = makeIcon('menu')
export const Network = makeIcon('network')
export const Play = makeIcon('zap')
export const RefreshCw = makeIcon('refresh')
export const ScanSearch = makeIcon('scan')
export const Server = makeIcon('server')
export const Shield = makeIcon('shield')
export const ShieldCheck = makeIcon('shieldCheck')
export const Sparkles = makeIcon('sparkles')
export const TerminalSquare = makeIcon('terminal')
export const TestTube2 = makeIcon('test')
export const Upload = makeIcon('upload')
export const X = makeIcon('x')
export const Zap = makeIcon('zap')

