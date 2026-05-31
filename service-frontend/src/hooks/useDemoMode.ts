import { selectDemoMode } from '@features/Auth/authSlice';
import { useAppSelector } from '@store/store';

export function useDemoMode(): boolean {
  return useAppSelector(selectDemoMode);
}
