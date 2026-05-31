type AuthHooks = {
  onUnauthorized?: () => void;
  onForbidden?: () => void;
};

const hooks: AuthHooks = {};

export function setAuthHooks(nextHooks: AuthHooks): void {
  hooks.onUnauthorized = nextHooks.onUnauthorized;
  hooks.onForbidden = nextHooks.onForbidden;
}

export function emitUnauthorized(): void {
  hooks.onUnauthorized?.();
}

export function emitForbidden(): void {
  hooks.onForbidden?.();
}
