import { useAppSelector } from '@store/store';
import type { AppRole } from '@/types/users';

export function useRole(): AppRole | null {
  return useAppSelector((state) => state.auth.role) as AppRole | null;
}

export function useAuthUserId(): number | null {
  return useAppSelector((state) => state.auth.userId);
}

export function useHasRole(required: AppRole): boolean {
  const role = useRole();

  if (role === null) {
    return false;
  }

  if (role === 'admin') {
    return true;
  }

  if (required === 'admin') {
    return false;
  }

  if (required === 'operator') {
    return role === 'operator';
  }

  return true;
}
