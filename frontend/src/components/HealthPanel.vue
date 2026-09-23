<template>
  <div class="panel">
    <div class="head">
      <h4>🩺 健康评分清单</h4>
      <div class="head-right">
        <span class="period-tag" :class="{ nodata: m.empty }">统计时段：{{ m.empty ? '-' : m.periodLabel }}</span>
        <el-button size="small" type="primary" :loading="exporting" @click="downloadReport">
          ⬇ 下载健康清单 (zip)
        </el-button>
      </div>
    </div>

    <div class="period-row">
      <span class="pr-label">选择统计时段：</span>
      <el-slider
        class="pr-slider"
        :model-value="sliderValue"
        :max="sliderMax"
        :min="0"
        :disabled="windows.length === 0"
        range
        :disabled-tooltip="false"
        :tooltip-formatter="fmtTip"
        @change="onSliderChange"
      />
      <span class="pr-count">{{ windows.length ? `共 ${windows.length} 个窗口（W0–W${windows.length - 1}，每窗口 1 分钟）` : '暂无窗口' }}</span>
    </div>

    <el-alert
      v-if="m.empty"
      class="reason"
      type="warning"
      :closable="false"
      show-icon
      title="当前无法生成健康评分"
      :description="m.reason"
    />

    <template v-else>
      <div class="cards">
        <div v-for="it in m.items" :key="it.key" class="card" :class="it.key">
          <div class="c-label">{{ it.label }}</div>
          <div class="c-value" :class="valueClass(it.key)">{{ it.value }}</div>
          <div class="c-detail">{{ it.detail }}</div>
        </div>
      </div>
      <div class="time-range">
        <span>📅 统计时段对应日志时间：</span>
        <span class="tr-val">{{ m.timeRangeLabel }}</span>
      </div>
      <div class="sources">
        <span class="s-label">来源在线情况：</span>
        <el-tag v-for="s in m.onlineSources" :key="s" size="small" type="success" effect="dark" class="s-tag">● {{ s }}</el-tag>
        <el-tag v-for="s in m.offlineSources" :key="s" size="small" type="info" effect="plain" class="s-tag">○ {{ s }}</el-tag>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useHealthReport, downloadBaseName, buildTextReport, buildJsonReport } from '../composables/useHealthReport'
import { buildZip } from '../utils/zip'

const { period, windows, metrics, setPeriod } = useHealthReport()
const m = metrics
const exporting = ref(false)

const sliderMax = computed(() => Math.max(windows.value.length - 1, 0))
const sliderValue = computed<[number, number]>(() => [period.value[0], period.value[1]])
const fmtTip = (v: number) => `W${v}`

function onSliderChange(val: [number, number] | number) {
  if (Array.isArray(val) && val.length === 2) setPeriod([val[0], val[1]])
}

function valueClass(key: string): string {
  const v = key === 'gen' ? m.value.rateScore
    : key === 'parse' ? m.value.parseRate * 100
    : key === 'online' ? m.value.onlineRate * 100
    : m.value.healthScore
  if (v >= 85) return 'good'
  if (v >= 60) return 'warn'
  return 'bad'
}

async function downloadReport() {
  // 连续点击保护：导出进行中直接忽略，保证一次点击只产生一份文件
  if (exporting.value) return
  const metricsSnapshot = m.value
  exporting.value = true
  try {
    // 让按钮 loading 有机会渲染，并顺带做短防抖，拦截快速连点
    await new Promise(r => setTimeout(r, 150))
    const base = downloadBaseName(metricsSnapshot)
    const zip = buildZip([
      { name: `${base}/健康评分清单.txt`, content: buildTextReport(metricsSnapshot) },
      { name: `${base}/health-report.json`, content: buildJsonReport(metricsSnapshot) }
    ])
    const url = URL.createObjectURL(zip)
    const a = document.createElement('a')
    a.href = url
    a.download = `${base}.zip`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    ElMessage.success(metricsSnapshot.empty
      ? '已下载说明文件：当前无可用统计数据，原因已写入文件'
      : `健康清单已下载（统计时段 ${metricsSnapshot.periodLabel}）`)
  } catch (e) {
    ElMessage.error('打包下载失败，请稍后重试')
  } finally {
    exporting.value = false
  }
}
</script>

<style scoped>
.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155}
.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:12px;flex-wrap:wrap}
.head h4{color:#38bdf8;font-size:13px}
.head-right{display:flex;align-items:center;gap:10px}
.period-tag{font-size:12px;color:#7dd3fc;background:#0c4a6e55;padding:2px 8px;border-radius:4px;border:1px solid #0369a155}
.period-tag.nodata{color:#94a3b8}
.period-row{display:flex;align-items:center;gap:12px;padding:2px 4px 6px}
.pr-label{font-size:12px;color:#94a3b8;white-space:nowrap}
.pr-slider{flex:1;max-width:520px}
.pr-count{font-size:11px;color:#64748b;white-space:nowrap}
.reason{margin:6px 0 2px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:6px}
.card{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:10px 12px}
.c-label{font-size:12px;color:#94a3b8;margin-bottom:4px}
.c-value{font-size:18px;font-weight:700;margin-bottom:6px}
.c-value.good{color:#4ade80}
.c-value.warn{color:#fbbf24}
.c-value.bad{color:#f87171}
.c-detail{font-size:11px;color:#64748b;line-height:1.5}
.time-range{margin-top:10px;font-size:12px;color:#94a3b8}
.tr-val{color:#cbd5e1}
.sources{margin-top:8px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.s-label{font-size:12px;color:#94a3b8}
.s-tag{margin:0}
</style>
