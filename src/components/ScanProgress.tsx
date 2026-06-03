import React, { useEffect, useRef } from 'react';
import { useStore } from '../store/useStore';
import { ScanProgressEvent } from '../types';

const ICONS: Record<string, string> = {
  crawl:   '🌐',
  probe:   '🔬',
  analyze: '⚡',
  fuzz:    '🎯',
  found:   '⚠',
  done:    '✓',
  error:   '✗',
};
const STAGES = ['crawl', 'probe', 'analyze', 'fuzz', 'done'];
const STAGE_LABELS: Record<string, string> = {
  crawl: 'Crawl',
  probe: 'Probe',
  analyze: 'Phân tích',
  fuzz: 'Fuzz',
  done: 'Hoàn tất',
};
const STAGE_PROGRESS: Record<string, number> = {
  crawl: 20,
  probe: 40,
  analyze: 65,
  fuzz: 85,
  done: 100,
};

export const ScanProgress: React.FC = () => {
  const { progressLog, stopScan, isLoading } = useStore();
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [progressLog.length]);

  const activeStage: string = progressLog.length > 0 ? progressLog[progressLog.length - 1].stage : '';
  const doneStages = new Set(progressLog.map((e) => e.stage));
  const logCount = progressLog.length;
  const progressPercent = STAGE_PROGRESS[activeStage] || (progressLog.length > 0 ? 10 : 0);
  const firstTs = progressLog.length > 0 ? progressLog[0].ts : Date.now();
  const elapsedSec = Math.max(0, Math.floor((Date.now() - firstTs) / 1000));
  const etaSec = progressPercent > 5 && progressPercent < 100
    ? Math.max(0, Math.round((elapsedSec / progressPercent) * (100 - progressPercent)))
    : 0;

  const formatSec = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m}:${sec.toString().padStart(2, '0')}`;
  };

  return (
    <div className="progress-panel">
      <div className="progress-panel-hdr">
        <div className="spinner-sm" />
        <span className="progress-panel-title">Đang quét…</span>
        <span className="progress-head-meta">{progressPercent}%</span>
        <span className="progress-head-meta">Đã chạy {formatSec(elapsedSec)}</span>
        {etaSec > 0 && <span className="progress-head-meta">ETA ~ {formatSec(etaSec)}</span>}
        <div style={{ flex: 1 }} />
        <span className="log-count-badge">{logCount} sự kiện</span>
        {isLoading && (
          <button
            className="btn-stop"
            onClick={stopScan}
            title="Dừng quét"
          >
            ■ Dừng
          </button>
        )}
      </div>

      <div className="progress-track-wrap" aria-label="Tiến trình quét tổng thể">
        <div className="progress-track-fill" style={{ width: `${progressPercent}%` }} />
      </div>

      {/* Pipeline các giai đoạn quét */}
      <div className="stage-pipeline">
        {STAGES.map((s) => {
          const stage = s as ScanProgressEvent['stage'];
          return (
            <React.Fragment key={s}>
              <div className={`stage-node ${doneStages.has(stage) ? 'done' : ''} ${activeStage === stage ? 'active' : ''}`}>
                <div className="stage-dot" />
                <span>{STAGE_LABELS[s] || s}</span>
              </div>
              {s !== 'done' && <div className={`stage-line ${doneStages.has(stage) ? 'done' : ''}`} />}
            </React.Fragment>
          );
        })}
      </div>

      {/* Nhật ký tiến trình */}
      <div className="progress-log">
        {progressLog.length === 0 && (
          <div className="log-line log-info"><span className="log-msg">Đang khởi tạo…</span></div>
        )}
        {progressLog.map((ev, i) => (
          <div key={i} className={`log-line log-${ev.level}`}>
            <span className="log-icon">{ICONS[ev.stage] || '·'}</span>
            <span className="log-ts">
              {new Date(ev.ts).toLocaleTimeString('vi-VN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
            <span className="log-msg">{ev.msg}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};
