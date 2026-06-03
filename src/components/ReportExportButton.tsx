import React from 'react';
import { useStore } from '../store/useStore';

export const ReportExportButton: React.FC = () => {
  const { exportReport, urlScanResult, projectScanResult, activeTab } = useStore();
  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
  if (!scanResult) return null;

  return (
    <div className="export-row">
      <button className="btn-secondary" onClick={() => exportReport('html')} title="Báo cáo dễ đọc để chia sẻ hoặc nộp bài">Báo cáo HTML</button>
      <button className="btn-secondary" onClick={() => exportReport('json')} title="Dữ liệu thô cho script hoặc công cụ khác">Dữ liệu JSON</button>
    </div>
  );
};
