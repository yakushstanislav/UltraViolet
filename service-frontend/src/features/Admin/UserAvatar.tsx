import type { AppRole } from '@/types/users';

type UserAvatarProps = {
  username: string;
  role: AppRole;
};

function initialsFor(username: string): string {
  const trimmed = username.trim();

  if (trimmed === '') {
    return '?';
  }

  const parts = trimmed.split(/[.\-_\s]+/).filter(Boolean);

  if (parts.length >= 2) {
    return (parts[0]![0]! + parts[1]![0]!).toUpperCase();
  }

  return trimmed.slice(0, 2).toUpperCase();
}

export function UserAvatar({ username, role }: UserAvatarProps) {
  return (
    <span
      aria-hidden
      className={`user-avatar user-avatar-${role}`}
      title={username}
    >
      {initialsFor(username)}
    </span>
  );
}
