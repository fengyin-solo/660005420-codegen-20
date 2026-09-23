// 纯前端 ZIP 打包（STORE 不压缩），避免引入额外依赖。
// 生成的 zip 可被系统自带解压工具与 Python zipfile 正常读取。

export interface ZipEntry { name: string; content: string }

const CRC_TABLE: Uint32Array = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
    t[n] = c >>> 0
  }
  return t
})()

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

const encoder = new TextEncoder()

function u16(v: number): number[] { return [v & 0xff, (v >>> 8) & 0xff] }
function u32(v: number): number[] { return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff] }

function dosDateTime(d: Date): { time: number; date: number } {
  return {
    time: ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((Math.floor(d.getSeconds() / 2)) & 0x1f),
    date: (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0x0f) << 5) | (d.getDate() & 0x1f)
  }
}

export function buildZip(entries: ZipEntry[]): Blob {
  const { time, date } = dosDateTime(new Date())
  const chunks: BlobPart[] = []
  const centralParts: number[] = []
  let offset = 0

  entries.forEach(entry => {
    const nameBytes = encoder.encode(entry.name)
    const data = encoder.encode(entry.content)
    const crc = crc32(data)
    const size = data.length

    // Local file header (signature 0x04034b50)
    const localHeader = Uint8Array.from([
      ...u32(0x04034b50), ...u16(20), ...u16(0x0800), ...u16(0),
      ...u16(time), ...u16(date), ...u32(crc), ...u32(size), ...u32(size),
      ...u16(nameBytes.length), ...u16(0)
    ])
    chunks.push(localHeader, nameBytes, data)

    // Central directory header (signature 0x02014b50)
    centralParts.push(
      ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0x0800), ...u16(0),
      ...u16(time), ...u16(date), ...u32(crc), ...u32(size), ...u32(size),
      ...u16(nameBytes.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
      ...u32(0), ...u32(offset)
    )
    centralParts.push(...nameBytes)

    offset += localHeader.length + nameBytes.length + size
  })

  const central = Uint8Array.from(centralParts)
  const endOfCentral = Uint8Array.from([
    ...u32(0x06054b50), ...u16(0), ...u16(0),
    ...u16(entries.length), ...u16(entries.length),
    ...u32(central.length), ...u32(offset), ...u16(0)
  ])

  return new Blob([...chunks, central, endOfCentral], { type: 'application/zip' })
}
