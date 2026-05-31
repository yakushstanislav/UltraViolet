import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

const startMarker = '__UV_MATCH_START__';
const endMarker = '__UV_MATCH_END__';
const previewCharLimit = 220;

type Props = {
  fragment?: string;
};

type Part = {
  text: string;
  highlighted: boolean;
};

export function SearchFragment({ fragment }: Props) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const parts = useMemo(
    () => (fragment ? splitFragment(fragment) : []),
    [fragment]
  );
  const totalLength = useMemo(
    () => parts.reduce((sum, part) => sum + part.text.length, 0),
    [parts]
  );

  if (!fragment) {
    return null;
  }

  const isLong = totalLength > previewCharLimit;
  const visibleParts =
    expanded || !isLong ? parts : truncateParts(parts, previewCharLimit);

  return (
    <div className="search-fragment">
      <span>
        {visibleParts.map((part, index) => {
          const key = `${index}-${part.highlighted ? 'h' : 't'}-${part.text.slice(0, 24)}`;

          return part.highlighted ? (
            <mark key={key}>{part.text}</mark>
          ) : (
            <span key={key}>{part.text}</span>
          );
        })}
      </span>
      {isLong && (
        <button
          className="search-fragment-toggle"
          onClick={() => setExpanded((value) => !value)}
          type="button"
        >
          {expanded
            ? t('searchFragment.showLess')
            : t('searchFragment.showMore')}
        </button>
      )}
    </div>
  );
}

function splitFragment(fragment: string): Part[] {
  const parts: Part[] = [];
  let highlighted = false;
  let cursor = 0;

  while (cursor < fragment.length) {
    const nextStart = fragment.indexOf(startMarker, cursor);
    const nextEnd = fragment.indexOf(endMarker, cursor);
    const nextMarker = nextMarkerIndex(nextStart, nextEnd);

    if (nextMarker === -1) {
      pushPart(parts, fragment.slice(cursor), highlighted);

      break;
    }

    pushPart(parts, fragment.slice(cursor, nextMarker), highlighted);

    if (nextMarker === nextStart) {
      highlighted = true;
      cursor = nextStart + startMarker.length;
    } else {
      highlighted = false;
      cursor = nextEnd + endMarker.length;
    }
  }

  return parts;
}

function nextMarkerIndex(nextStart: number, nextEnd: number): number {
  if (nextStart === -1) {
    return nextEnd;
  }

  if (nextEnd === -1) {
    return nextStart;
  }

  return Math.min(nextStart, nextEnd);
}

function pushPart(parts: Part[], text: string, highlighted: boolean) {
  if (text === '') {
    return;
  }

  parts.push({ text, highlighted });
}

function truncateParts(parts: Part[], maxLength: number): Part[] {
  let remaining = maxLength;
  const result: Part[] = [];

  for (const part of parts) {
    if (remaining <= 0) {
      break;
    }

    if (part.text.length <= remaining) {
      result.push(part);
      remaining -= part.text.length;
      continue;
    }

    result.push({
      text: `${part.text.slice(0, remaining)}...`,
      highlighted: part.highlighted,
    });
    remaining = 0;
  }

  return result;
}
