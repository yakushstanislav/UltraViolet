export type MeResponse = {
  role: 'viewer' | 'operator' | 'admin';
  user_id: number;
};

export type LoginRequest = {
  username: string;
  password: string;
};

export type RefreshRequest = {
  refresh_token: string;
};

export type AuthTokenResponse = {
  access_token: string;
  refresh_token: string;
  role: MeResponse['role'];
};
