export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow {
  start: number
  end: number
  count: number
  levels: Record<string, number>
  sources: Record<string, number>
  parsed: number
  startTs: string
  endTs: string
}
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; timestamp: string }
export interface AlertRule { id: number; name: string; type: string; threshold: number; enabled: boolean }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
export interface AnalysisResult {
  logs: LogEntry[]
  windows: TimeWindow[]
  anomalies: AnomalyScore[]
  alerts: Alert[]
  totalLogs: number
  logType?: string
  windowSize?: number
  windowSeconds?: number
}
