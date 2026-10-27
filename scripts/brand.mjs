#!/usr/bin/env node
// 生成 brand/icon.png 与 brand/social-preview.png。
//
// 契约见 SForum docs/extensions/brand-assets.md：512×512 RGBA 图标、
// 1280×640 社交卡。品牌字形直接复用 SForum 官方 logo 的路径，不自造标记。
// 生成不是 CI 步骤 —— 产物入库，流水线只跑 `extension brand check`。

import { createRequire } from 'node:module'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const packageDir = path.join(repoRoot, 'plugins', 'sforum.connect')
const brandDir = path.join(packageDir, 'brand')
const logoFile = path.join(repoRoot, '..', 'SForum', 'apps', 'web', 'public', 'brand', 'sforum-logo.svg')

const BRAND_START = '#2671ed'
const BRAND_END = '#1f6bec'
const INK = '#f4f8fd'
const INK_SOFT = '#b9c7d8'
const INK_MUTE = '#8fa0b8'
const INK_FAINT = '#5b6b85'
const CANVAS = '#0b1220'
const HAIRLINE = 'rgba(255,255,255,0.08)'

const FONT_SANS = "'Noto Sans CJK SC','Noto Sans CJK','Noto Sans','DejaVu Sans',sans-serif"
const FONT_MONO = "'DejaVu Sans Mono','Noto Sans Mono',monospace"

function loadSharp() {
  const candidates = [
    path.join(repoRoot, '..', 'SForum', 'apps', 'web', 'node_modules', 'sharp'),
    ...(process.env.NODE_PATH
      ? process.env.NODE_PATH.split(path.delimiter).filter(Boolean).map((entry) => path.join(entry, 'sharp'))
      : []),
    path.join(os.homedir(), '.bun/install/global/node_modules/sharp')
  ]
  for (const candidate of candidates) {
    try {
      return require(candidate)
    } catch {
      // 继续尝试下一个来源：生成是维护者任务，不绑定单一安装位置。
    }
  }
  throw new Error('找不到 sharp。请在 SForum/apps/web 跑 bun install，或把 NODE_PATH 指向已安装 sharp 的 node_modules。')
}

function escapeXML(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function readManifest() {
  return JSON.parse(fs.readFileSync(path.join(packageDir, 'sforum.extension.json'), 'utf8'))
}

// 把 SForum logo 的内联内容嵌进指定矩形；viewBox 裁掉 logo 自带的留白。
function logoMarkup(x, y, size) {
  const raw = fs.readFileSync(logoFile, 'utf8')
  const inner = raw
    .replace(/^<\?xml[^>]*\?>\s*/i, '')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/i, '')
  return `<svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="20 20 270 270">${inner}</svg>`
}

function cardSVG(manifest) {
  const meta = [
    `<tspan fill="${INK_FAINT}">${escapeXML(manifest.id)}</tspan>`,
    `<tspan fill="#475569">   ·   </tspan>`,
    `<tspan fill="#4d7fd6">v${escapeXML(manifest.version)}</tspan>`
  ].join('')

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640">
  <defs>
    <linearGradient id="wash" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0.4" stop-color="${BRAND_START}" stop-opacity="0"/>
      <stop offset="1" stop-color="${BRAND_START}" stop-opacity="0.14"/>
    </linearGradient>
    <linearGradient id="tile" x1="0" y1="0" x2="0.35" y2="1">
      <stop offset="0" stop-color="#101b2d"/>
      <stop offset="1" stop-color="${CANVAS}"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="${BRAND_START}" stop-opacity="0.17"/>
      <stop offset="1" stop-color="${BRAND_START}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1280" height="640" fill="${CANVAS}"/>
  <rect width="1280" height="640" fill="url(#wash)"/>
  <rect x="24.5" y="24.5" width="1231" height="591" rx="20" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="1"/>
  <line x1="792" y1="150" x2="792" y2="500" stroke="rgba(255,255,255,0.06)" stroke-width="1"/>

  <text x="88" y="176" font-family="${FONT_SANS}" font-size="14" fill="#6b7d94"><tspan letter-spacing="3">SFORUM</tspan><tspan dx="7" letter-spacing="0.5">· 扩展插件</tspan></text>
  <text x="88" y="282" font-family="${FONT_SANS}" font-size="64" font-weight="700" fill="${INK}">SForum 账号登录</text>
  <text x="88" y="326" font-family="${FONT_SANS}" font-size="20" fill="${INK_MUTE}">${escapeXML(manifest.name)}</text>
  <text x="88" y="396" font-family="${FONT_SANS}" font-size="26" fill="${INK_SOFT}">用 SForum 账号登录你的社区</text>
  <text x="88" y="446" font-family="${FONT_MONO}" font-size="16">${meta}</text>

  <circle cx="1016" cy="320" r="260" fill="url(#glow)"/>
  <rect x="856" y="160" width="320" height="320" rx="72" fill="url(#tile)"/>
  <rect x="856.5" y="160.5" width="319" height="319" rx="71.5" fill="none" stroke="${HAIRLINE}" stroke-width="1"/>
  ${logoMarkup(901, 205, 230)}

  <g transform="translate(88 556)">${logoMarkup(0, 0, 28)}</g>
  <text x="128" y="577" font-family="${FONT_SANS}" font-size="19" font-weight="600" fill="#dce5f2">SForum</text>
  <text x="1192" y="577" text-anchor="end" font-family="${FONT_MONO}" font-size="14" fill="#46586f">keeptrue/sforum-connect</text>
</svg>
`
}

async function writeAsset(sharp, svg, file, width, height) {
  const buffer = await sharp(Buffer.from(svg)).png({ compressionLevel: 9 }).toBuffer()
  fs.writeFileSync(file, buffer)
  const meta = await sharp(buffer).metadata()
  if (meta.width !== width || meta.height !== height) {
    throw new Error(`${file}: ${meta.width}x${meta.height}, want ${width}x${height}`)
  }
  return {
    file: path.relative(repoRoot, file),
    bytes: buffer.length,
    digest: crypto.createHash('sha256').update(buffer).digest('hex').slice(0, 12)
  }
}

async function main() {
  const sharp = loadSharp()
  const manifest = readManifest()
  const iconSVG = fs.readFileSync(path.join(brandDir, 'icon.svg'), 'utf8')

  const outputs = [
    await writeAsset(sharp, iconSVG, path.join(brandDir, 'icon.png'), 512, 512),
    await writeAsset(sharp, cardSVG(manifest), path.join(brandDir, 'social-preview.png'), 1280, 640)
  ]
  for (const output of outputs) {
    console.log(`${output.file}\t${output.bytes} bytes\tsha256:${output.digest}…`)
  }
}

await main()
