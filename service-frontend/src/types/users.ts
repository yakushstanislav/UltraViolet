export type AppRole = 'viewer' | 'operator' | 'admin';

export type User = {
  id: number;
  username: string;
  role: AppRole;
  is_active: boolean;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
};

export type UserListResponse = {
  page: number;
  limit: number;
  total: number;
  users: User[];
};

export type CreateUserRequest = {
  username: string;
  password: string;
  role: AppRole;
};
