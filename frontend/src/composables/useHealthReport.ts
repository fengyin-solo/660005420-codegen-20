import { ref, computed } from 'vue'
import { useLogStore } from '../store/log'
import type { AnalysisResult } from '@/types'

// 每个统计窗口代表 1 分钟（与后端窗口划分一致）
const MINUTES_PER_WINDOW = 1
// 生成速率的基准目标：20 条/分钟（每个 1 分钟窗口 20 条）
const TARGET_RATE_PER_MIN = 20
const STORAGE_KEY = 'health-report-period'

// 模块级状态：刷新后重新进入页面时仍保留上一次选中的时段
function loadPeriod(): [number, number] | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const arr = JSON.parse(raw)
      if (Array.isArray(arr) && arr.length === 2 && arr.every(v => Number.isInteger(v) && v >= 0)) {
        return arr[0] <= arr[1] ? [arr[0], arr[1]] : [arr[1], arr[0]]
      }
    }
  } catch { /* localStorage 不可用或缓存损坏：使用默认时段 */ }
  return null
}

const period = ref<[number, number]>([0, 49])
let periodLoaded = false

function ensurePeriodLoaded() {
  if (periodLoaded) return
  periodLoaded = true
  const saved = loadPeriod()
  if (saved) period.value = saved
}

function persistPeriod() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(period.value)) } catch { /* 忽略写入失败 */ }
}

export interface HealthItem {
  key: string
  label: string
  value: string
  detail: string
}

export interface HealthMetrics {
  empty: boolean
  reason: string
  windowCount: number
  from: number
  to: number
  periodLabel: string
  timeRangeLabel: string
  totalCount: number
  parsedCount: number
  onlineSources: string[]
  offlineSources: string[]
  genRatePerMin: number
  genRatePerSec: number
  rateScore: number
  parseRate: number
  onlineRate: number
  healthScore: number
  items: HealthItem[]
}

const pct = (v: number) => `${(v * 100).toFixed(1)}%`

export function useHealthReport() {
  const store = useLogStore()
  ensurePeriodLoaded()
  const result = computed<AnalysisResult | null>(() => store.result)
  const windows = computed(() => result.value?.windows ?? [])

  // 窗口数量变化（重新生成/检测）后，把已选时段收敛到合法范围，但保留用户选择倾向
  function clampPeriod(): [number, number] {
    const n = windows.value.length
    if (n === 0) return period.value
    let [a, b] = period.value
    a = Math.min(a, n - 1)
    b = Math.min(b, n - 1)
    if (a > b) a = b
    if (a !== period.value[0] || b !== period.value[1]) {
      period.value = [a, b]
      persistPeriod()
    }
    return period.value
  }

  function setPeriod(v: [number, number]) {
    period.value = v
    persistPeriod()
  }

  const metrics = computed<HealthMetrics>(() => {
    const res = result.value
    const base: HealthMetrics = {
      empty: true, reason: '', windowCount: 0,
      from: 0, to: 0, periodLabel: '-', timeRangeLabel: '-',
      totalCount: 0, parsedCount: 0, onlineSources: [], offlineSources: [],
      genRatePerMin: 0, genRatePerSec: 0, rateScore: 0, parseRate: 0, onlineRate: 0,
      healthScore: 0, items: []
    }
    if (!res) {
      base.reason = '尚未生成或分析日志，页面没有任何统计数据。请先在顶部选择日志类型并点击“生成日志”，再选择统计时段导出。'
      return base
    }
    const ws = res.windows ?? []
    if (ws.length === 0) {
      base.reason = '当前结果中没有任何统计窗口（日志总数为 0），因此生成速率、解析成功率与在线率均无法计算。请重新生成日志后再导出。'
      return base
    }
    const [a, b] = clampPeriod()
    const selected = ws.slice(a, b + 1)
    if (selected.length === 0) {
      base.reason = `所选时段 W${a}–W${b} 不在当前窗口范围（共 ${ws.length} 个窗口）内，请重新选择时段。`
      return base
    }

    const totalCount = selected.reduce((s, w) => s + w.count, 0)
    if (totalCount === 0) {
      base.reason = `所选时段 W${a}–W${b} 内日志条数为 0，无法计算生成速率与解析成功率，请选择其他时段。`
      return base
    }
    const parsedCount = selected.reduce((s, w) => s + (w.parsed ?? 0), 0)
    const roster = res.sourceRoster ?? []
    const present = new Set<string>()
    selected.forEach(w => Object.keys(w.sources ?? {}).forEach(s => present.add(s)))
    const onlineSources = roster.filter(s => present.has(s))
    const offlineSources = roster.filter(s => !present.has(s))
    // 兜底：后端未返回来源清单时，用实际出现的来源作为清单
    const rosterCount = roster.length > 0 ? roster.length : present.size
    if (roster.length === 0) present.forEach(s => onlineSources.push(s))

    const minutes = selected.length * MINUTES_PER_WINDOW
    const genRatePerMin = totalCount / minutes
    const genRatePerSec = genRatePerMin / 60
    const rateScore = Math.min(100, (genRatePerMin / TARGET_RATE_PER_MIN) * 100)
    const parseRate = parsedCount / totalCount
    const onlineRate = rosterCount > 0 ? onlineSources.length / rosterCount : 1
    const healthScore = Math.round(rateScore * 0.2 + parseRate * 100 * 0.5 + onlineRate * 100 * 0.3)

    const periodLabel = `W${a}–W${b}（${selected.length} 个窗口 / ${minutes} 分钟）`
    const timeRangeLabel = `${selected[0].firstTimestamp || '-'} ~ ${selected[selected.length - 1].lastTimestamp || '-'}`

    const items: HealthItem[] = [
      {
        key: 'gen', label: '生成速率',
        value: `${genRatePerMin.toFixed(1)} 条/分钟（${genRatePerSec.toFixed(2)} 条/秒）`,
        detail: `所选时段共 ${totalCount} 条日志 / ${minutes} 分钟；基准目标 ${TARGET_RATE_PER_MIN} 条/分钟，得分 ${rateScore.toFixed(1)}/100`
      },
      {
        key: 'parse', label: '解析成功率',
        value: pct(parseRate),
        detail: `${parsedCount}/${totalCount} 条原始报文解析成功，${totalCount - parsedCount} 条残缺或无法解析；得分 ${(parseRate * 100).toFixed(1)}/100`
      },
      {
        key: 'online', label: '在线率',
        value: pct(onlineRate),
        detail: rosterCount > 0
          ? `${onlineSources.length}/${rosterCount} 个来源在线；离线：${offlineSources.length ? offlineSources.join('、') : '无'}`
          : '未配置来源清单，在线率按 100% 计'
      },
      {
        key: 'score', label: '综合健康评分',
        value: `${healthScore} / 100`,
        detail: '加权公式：生成速率得分 × 20% + 解析成功率 × 50% + 在线率 × 30%'
      }
    ]

    return {
      empty: false, reason: '', windowCount: ws.length,
      from: a, to: b, periodLabel, timeRangeLabel,
      totalCount, parsedCount, onlineSources, offlineSources,
      genRatePerMin, genRatePerSec, rateScore, parseRate, onlineRate, healthScore, items
    }
  })

  return { period, windows, result, metrics, setPeriod }
}

// ---- 打包文件内容：与页面卡片共用 metrics.items，保证逐条吻合 ----

export function downloadBaseName(m: HealthMetrics): string {
  const ts = new Date()
  const p = (v: number) => String(v).padStart(2, '0')
  const stamp = `${ts.getFullYear()}${p(ts.getMonth() + 1)}${p(ts.getDate())}_${p(ts.getHours())}${p(ts.getMinutes())}${p(ts.getSeconds())}`
  return m.empty ? `health-report_nodata_${stamp}` : `health-report_W${m.from}-W${m.to}_${stamp}`
}

export function buildTextReport(m: HealthMetrics): string {
  const lines: string[] = []
  lines.push('日志引擎健康评分清单')
  lines.push('=' .repeat(40))
  lines.push(`生成时间：${new Date().toLocaleString()}`)
  if (m.empty) {
    lines.push('')
    lines.push('【无数据】本次未生成健康评分条目，原因如下：')
    lines.push(m.reason)
    return lines.join('\n')
  }
  lines.push(`统计时段：窗口 ${m.periodLabel}`)
  lines.push(`时间范围：${m.timeRangeLabel}`)
  lines.push('')
  m.items.forEach((it, i) => {
    lines.push(`${i + 1}. ${it.label}`)
    lines.push(`   当前值：${it.value}`)
    lines.push(`   说明：${it.detail}`)
  })
  lines.push('')
  lines.push(`在线来源：${m.onlineSources.length ? m.onlineSources.join('、') : '无'}`)
  lines.push(`离线来源：${m.offlineSources.length ? m.offlineSources.join('、') : '无'}`)
  lines.push('')
  lines.push('注：文件中的各项数值与页面健康评分面板当前显示逐条一致。')
  return lines.join('\n')
}

export function buildJsonReport(m: HealthMetrics): string {
  if (m.empty) {
    return JSON.stringify({
      report: '日志引擎健康评分清单',
      generatedAt: new Date().toISOString(),
      hasData: false,
      reason: m.reason
    }, null, 2)
  }
  return JSON.stringify({
    report: '日志引擎健康评分清单',
    generatedAt: new Date().toISOString(),
    hasData: true,
    period: { fromWindow: m.from, toWindow: m.to, windowCount: m.to - m.from + 1, minutes: m.to - m.from + 1 },
    timeRange: m.timeRangeLabel,
    items: m.items.map(it => ({ label: it.label, value: it.value, detail: it.detail })),
    sources: { online: m.onlineSources, offline: m.offlineSources }
  }, null, 2)
}
