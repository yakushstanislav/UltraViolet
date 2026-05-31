const ADJECTIVES = [
  'able',
  'brisk',
  'calm',
  'clever',
  'curious',
  'eager',
  'gentle',
  'happy',
  'jolly',
  'kind',
  'lively',
  'modest',
  'nimble',
  'polite',
  'proud',
  'quiet',
  'serene',
  'swift',
  'witty',
  'zealous',
] as const;

const NOUNS = [
  'badger',
  'beacon',
  'coral',
  'crane',
  'falcon',
  'forest',
  'harbor',
  'heron',
  'lotus',
  'meadow',
  'nova',
  'orchid',
  'otter',
  'panda',
  'quartz',
  'raven',
  'river',
  'spruce',
  'summit',
  'violet',
] as const;

function pickWord<T extends readonly string[]>(words: T): T[number] {
  const index = Math.floor(Math.random() * words.length);

  return words[index]!;
}

function capitalize(word: string): string {
  if (word.length === 0) {
    return word;
  }

  return word[0]!.toUpperCase() + word.slice(1);
}

/** Human-readable default scan name (PascalCase adjective+noun), similar in spirit to Docker names. */
export function generateRandomScanName(): string {
  return `${capitalize(pickWord(ADJECTIVES))}${capitalize(pickWord(NOUNS))}`;
}
