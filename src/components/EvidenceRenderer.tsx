import React from 'react';

type CodeSnippetLine = { line: string; code: string; active: boolean };
type RenderEvidenceOptions = {
  path?: string;
};

function parseEvidenceSnippet(evidence: string): CodeSnippetLine[] | null {
  if (!/(?:Doan code lien quan|Đoạn code liên quan):/i.test(evidence)) return null;
  const rawLines = evidence.split('\n').slice(1);
  const rows = rawLines
    .map((line) => {
      const match = line.match(/^([ >])\s*(\d+)\s\|\s?(.*)$/);
      if (!match) return null;
      return {
        active: match[1] === '>',
        line: match[2],
        code: match[3] || ' ',
      };
    })
    .filter((row): row is CodeSnippetLine => Boolean(row));
  return rows.length ? rows : null;
}

export function localizeEvidenceText(evidence: string): string {
  return evidence
    .replace(/Dong nghi van:/gi, 'Dòng nghi vấn:')
    .replace(/Doan code lien quan:/gi, 'Đoạn code liên quan:');
}

export function renderEvidence(evidence: string, index: number, options: RenderEvidenceOptions = {}): React.ReactNode {
  const localizedEvidence = localizeEvidenceText(evidence);
  const snippet = parseEvidenceSnippet(localizedEvidence);
  if (snippet) {
    const activeLine = snippet.find((line) => line.active)?.line;
    return (
      <div key={index} className="detail-code-snippet">
        <div className="code-snippet-head">
          <span className="code-snippet-title-wrap">
            <span>Đoạn code liên quan</span>
            {options.path && <span className="code-snippet-path" title={options.path}>{options.path}</span>}
          </span>
          {activeLine && <strong>Dòng lỗi: {activeLine}</strong>}
        </div>
        <pre className="code-snippet-body">
          {snippet.map((row) => (
            <span key={`${row.line}-${row.code}`} className={`code-snippet-row${row.active ? ' is-active' : ''}`}>
              <span className="code-snippet-marker">{row.active ? '!' : ''}</span>
              <span className="code-snippet-line">{row.line}</span>
              <span className="code-snippet-code">{row.code}</span>
            </span>
          ))}
        </pre>
      </div>
    );
  }

  const lineMatch = localizedEvidence.match(/Dòng nghi vấn:\s*(\d+)/i);
  if (lineMatch) {
    return (
      <div key={index} className="detail-line-callout">
        <span>Dòng cần kiểm tra</span>
        <strong>{lineMatch[1]}</strong>
      </div>
    );
  }

  return <div key={index} className="detail-evidence">{localizedEvidence}</div>;
}
