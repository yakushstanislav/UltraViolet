type NavigatorWithUAData = Navigator & {
  userAgentData?: { platform?: string };
};

export function isMac(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  const nav = window.navigator as NavigatorWithUAData;
  const platform = nav.userAgentData?.platform;
  if (typeof platform === 'string' && platform !== '') {
    return /mac/i.test(platform);
  }

  return /Mac|iPhone|iPod|iPad/.test(window.navigator.userAgent);
}

export function getKbdHint(letter: string): string {
  const upper = letter.toUpperCase();

  return isMac() ? `⌘${upper}` : `Ctrl ${upper}`;
}

export function readKbdHintAriaLabel(hint: string): string {
  return hint.replace('⌘', 'Command ');
}
