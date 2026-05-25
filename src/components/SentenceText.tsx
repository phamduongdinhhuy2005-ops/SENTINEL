import React from 'react';

type SentenceTextProps = {
  text?: string;
  className?: string;
  as?: 'div' | 'span' | 'p';
};

const SENTENCE_BOUNDARY = /(?<=[.!?])\s+(?=[0-9A-ZÀÁẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬĐÈÉẺẼẸÊẾỀỂỄỆÌÍỈĨỊÒÓỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÙÚỦŨỤƯỨỪỬỮỰỲÝỶỸỴ])/gu;

function shouldKeepInline(text: string): boolean {
  if (/https?:\/\/|[A-Z]:\\|\/[\w.-]+\/|```|<[^>]+>/.test(text)) return true;
  return false;
}

export function splitReadableSentences(value?: string): string[] {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return [];
  if (shouldKeepInline(text)) return [text];
  return text.split(SENTENCE_BOUNDARY).map((item) => item.trim()).filter(Boolean);
}

export const SentenceText: React.FC<SentenceTextProps> = ({ text, className = '', as = 'div' }) => {
  const Tag = as;
  const sentences = splitReadableSentences(text);

  return (
    <Tag className={`sentence-text ${className}`.trim()}>
      {sentences.map((sentence, index) => (
        <span key={`${index}-${sentence.slice(0, 18)}`} className="sentence-text-line">
          {sentence}
        </span>
      ))}
    </Tag>
  );
};
