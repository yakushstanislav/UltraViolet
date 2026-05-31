import type {
  AppRole,
  CreateUserRequest,
  User,
  UserListResponse,
} from '@/types/users';

import { apiClient } from './apiClient';

export async function listUsers(
  page = 1,
  limit = 25,
  filters?: { q?: string; role?: string }
): Promise<UserListResponse> {
  const response = await apiClient.get<UserListResponse>('/v1/users', {
    params: {
      page,
      limit,
      ...(filters?.q ? { q: filters.q } : {}),
      ...(filters?.role ? { role: filters.role } : {}),
    },
  });

  return response.data;
}

export async function createUser(payload: CreateUserRequest): Promise<User> {
  const response = await apiClient.post<User>('/v1/users', payload);

  return response.data;
}

export async function changeUserRole(id: number, role: AppRole): Promise<User> {
  const response = await apiClient.patch<User>(`/v1/users/${id}/role`, {
    role,
  });

  return response.data;
}

export async function resetUserPassword(
  id: number,
  password: string
): Promise<void> {
  await apiClient.patch(`/v1/users/${id}/password`, { password });
}

export async function setUserActive(id: number, active: boolean): Promise<User> {
  const response = await apiClient.patch<User>(`/v1/users/${id}/active`, {
    active,
  });

  return response.data;
}

export async function deleteUser(id: number): Promise<void> {
  await apiClient.delete(`/v1/users/${id}`);
}
