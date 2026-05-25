function lineFromIndex(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function snippetAround(content, lineNumber, radius = 2) {
  const lines = content.split(/\r?\n/);
  const start = Math.max(1, lineNumber - radius);
  const end = Math.min(lines.length, lineNumber + radius);
  const snippet = [];

  for (let line = start; line <= end; line += 1) {
    const marker = line === lineNumber ? '>' : ' ';
    snippet.push(`${marker} ${String(line).padStart(4, ' ')} | ${lines[line - 1]}`);
  }

  return { start, end, snippet: snippet.join('\n') };
}

function singleUseRegex(pattern, global = false) {
  if (!(pattern instanceof RegExp)) return null;
  const flags = pattern.flags.replace(/g/g, '');
  return new RegExp(pattern.source, global ? `${flags}g` : flags);
}

function scoreLine(line, focusPatterns) {
  let score = 0;
  for (const pattern of focusPatterns) {
    if (pattern.test(line)) score += 12;
  }
  if (/(req\.|request\.|params\.|query\.|body\.|userInput|\$_(?:GET|POST|REQUEST))/i.test(line)) score += 4;
  if (/(sequelize\.query|findByPk|findOne|findAll|update|destroy|fetch|axios|https?\.get|request|redirect|yaml\.load|parseXml|serveIndex|curl_setopt|file_get_contents)/i.test(line)) score += 6;
  if (/[({.[=]/.test(line)) score += 1;
  if (!line.trim()) score -= 20;
  return score;
}

function bestLineInMatch(content, match, focusPatterns) {
  const lines = content.split(/\r?\n/);
  const matchLineStart = lineFromIndex(content, match.index);
  const matchLineEnd = lineFromIndex(content, match.index + match[0].length);
  let bestLine = matchLineStart;
  let bestScore = Number.NEGATIVE_INFINITY;

  for (let lineNumber = matchLineStart; lineNumber <= matchLineEnd; lineNumber += 1) {
    const score = scoreLine(lines[lineNumber - 1] || '', focusPatterns);
    if (score > bestScore) {
      bestScore = score;
      bestLine = lineNumber;
    }
  }

  return bestLine;
}

function matchCandidates(content, pattern, limit = 25) {
  const regex = singleUseRegex(pattern, true);
  if (!regex) return [];
  const candidates = [];
  let match;

  while ((match = regex.exec(content)) && candidates.length < limit) {
    candidates.push(match);
    if (match[0].length === 0) regex.lastIndex += 1;
  }

  return candidates;
}

function locatePattern(content, patterns, options = {}) {
  const radius = options.radius ?? 2;
  const items = Array.isArray(patterns) ? patterns : [patterns];
  const defaultFocusPatterns = options.focusPatterns || [];
  let best = null;
  let bestScore = Number.NEGATIVE_INFINITY;

  for (const item of items) {
    const pattern = item instanceof RegExp ? item : item?.re;
    const focusPatterns = [
      ...defaultFocusPatterns,
      ...(!item || item instanceof RegExp ? [] : item.focusPatterns || []),
    ];
    const matches = matchCandidates(content, pattern);

    for (const match of matches) {
      if (!match || typeof match.index !== 'number') continue;

      const focusLine = bestLineInMatch(content, match, focusPatterns);
      const around = snippetAround(content, focusLine, radius);
      const candidateScore = scoreLine((content.split(/\r?\n/)[focusLine - 1] || ''), focusPatterns) - Math.min(match[0].length / 1000, 8);

      if (candidateScore > bestScore) {
        bestScore = candidateScore;
        best = {
          lineStart: focusLine,
          lineEnd: focusLine,
          snippetStart: around.start,
          snippetEnd: around.end,
          snippet: around.snippet,
          matchedText: (content.split(/\r?\n/)[focusLine - 1] || match[0]).trim().slice(0, 500),
        };
      }
    }
  }

  return best;
}

function evidenceWithLocation(evidence, locator) {
  const lines = Array.isArray(evidence) ? evidence.filter(Boolean) : [evidence].filter(Boolean);
  if (!locator) return lines;
  return [
    ...lines,
    `Dòng nghi vấn: ${locator.lineStart}`,
    `Đoạn code liên quan:\n${locator.snippet}`,
  ];
}

function buildSourceRemediationPlan({ filePath, locator, summary, suggestedFrom, suggestedTo }) {
  const lineHint = locator
    ? `${filePath}:${locator.lineStart}${locator.lineEnd > locator.lineStart ? `-${locator.lineEnd}` : ''}`
    : filePath;

  return {
    summary,
    locationHint: `Project Scan: kiểm tra ${lineHint}.`,
    confidenceNote:
      'Đề xuất này được suy luận từ pattern source code và chỉ mang tính tham khảo; hãy phân tích kỹ ngữ cảnh trước khi sửa.',
    suggestedChange: {
      from: suggestedFrom || locator?.matchedText || 'Đoạn code khớp mẫu lỗi trong snippet.',
      to: suggestedTo || summary,
    },
    steps: [
      `Mở ${lineHint} và đối chiếu snippet/bằng chứng với luồng xử lý thực tế.`,
      summary,
      'Sau khi sửa, chạy lại scan và test liên quan để xác nhận không phát sinh lỗi chức năng.',
    ],
  };
}

module.exports = {
  locatePattern,
  evidenceWithLocation,
  buildSourceRemediationPlan,
};
