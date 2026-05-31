const regionalIndicatorA = 0x1f1e6;
const asciiA = 0x41;

// ISO 3166-1 alpha-2 → regional indicator flag pair (emoji).
export function countryCodeToFlagEmoji(code: string): string {
  const upper = code.toUpperCase();

  if (upper.length !== 2) {
    return '';
  }

  const a = upper.codePointAt(0);
  const b = upper.codePointAt(1);

  if (
    a === undefined ||
    b === undefined ||
    a < asciiA ||
    a > asciiA + 25 ||
    b < asciiA ||
    b > asciiA + 25
  ) {
    return '';
  }

  return String.fromCodePoint(
    regionalIndicatorA + (a - asciiA),
    regionalIndicatorA + (b - asciiA)
  );
}
