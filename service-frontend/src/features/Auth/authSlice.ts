import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import axios from 'axios';

import { extractApiErrorMessage } from '@helpers/apiError';
import i18n from '@i18n/i18n';
import { getMe, login, logout, refresh } from '@services/AuthAPI';
import { getVersion } from '@services/VersionAPI';
import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  setAccessToken,
  setRefreshToken,
} from '@storage/accessToken';
import type { MeResponse } from '@/types/api';

type AuthState = {
  role: MeResponse['role'] | null;
  userId: number | null;
  demoMode: boolean;
  loading: boolean;
  error: string | null;
};

const initialState: AuthState = {
  role: null,
  userId: null,
  demoMode: false,
  loading: true,
  error: null,
};

export const loadMe = createAsyncThunk('auth/me', () => getMe());
export const loginUser = createAsyncThunk<
  MeResponse,
  { username: string; password: string },
  { rejectValue: string }
>('auth/login', async (credentials, { rejectWithValue }) => {
  try {
    const response = await login(credentials);
    setAccessToken(response.access_token);
    setRefreshToken(response.refresh_token);

    return getMe();
  } catch (error: unknown) {
    const fallback =
      axios.isAxiosError(error) && error.response?.status === 401
        ? i18n.t('auth.errors.invalidCredentials')
        : i18n.t('auth.errors.unableToSignIn');

    return rejectWithValue(extractApiErrorMessage(error, fallback));
  }
});

export const logoutUser = createAsyncThunk('auth/logout', async () => {
  const refreshToken = getRefreshToken();
  if (refreshToken !== '') {
    try {
      await logout({ refresh_token: refreshToken });
    } catch {
      // Keep local logout reliable even if API logout fails.
    }
  }

  clearAuthTokens();
});

export const restoreSession = createAsyncThunk('auth/restore', async () => {
  const refreshToken = getRefreshToken();
  if (refreshToken === '') {
    throw new Error('No refresh token');
  }

  const response = await refresh({ refresh_token: refreshToken });
  setAccessToken(response.access_token);
  setRefreshToken(response.refresh_token);

  return getMe();
});

export const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    resetAuth: (state) => {
      state.role = null;
      state.userId = null;
      state.error = null;
      state.loading = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loadMe.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadMe.fulfilled, (state, action) => {
        state.loading = false;
        state.role = action.payload.role;
        state.userId = action.payload.user_id;
      })
      .addCase(loadMe.rejected, (state, action) => {
        state.loading = false;
        state.role = null;
        state.userId = null;
        state.error =
          action.error.message ?? i18n.t('auth.errors.requestFailed');
      })
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.role = action.payload.role;
        state.userId = action.payload.user_id;
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.role = null;
        state.userId = null;
        state.error =
          action.payload ??
          action.error.message ??
          i18n.t('auth.errors.loginFailed');
      })
      .addCase(logoutUser.fulfilled, (state) => {
        state.loading = false;
        state.role = null;
        state.userId = null;
        state.error = null;
      })
      .addCase(restoreSession.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(restoreSession.fulfilled, (state, action) => {
        state.loading = false;
        state.role = action.payload.role;
        state.userId = action.payload.user_id;
      })
      .addCase(restoreSession.rejected, (state, action) => {
        state.loading = false;
        state.role = null;
        state.userId = null;
        state.error =
          action.error.message ?? i18n.t('auth.errors.sessionExpired');
      })
      .addCase(fetchDemoMode.fulfilled, (state, action) => {
        state.demoMode = action.payload;
      });
  },
});

export const { resetAuth } = authSlice.actions;

// Selectors
export const selectDemoMode = (state: { auth: AuthState }) =>
  state.auth.demoMode;

export const fetchDemoMode = createAsyncThunk('auth/demoMode', async () => {
  const version = await getVersion();
  return version.demo_mode;
});

export const bootstrapAuth = createAsyncThunk(
  'auth/bootstrap',
  async (_, { dispatch }) => {
    void dispatch(fetchDemoMode());

    if (getAccessToken() !== '') {
      await dispatch(loadMe());

      return;
    }

    if (getRefreshToken() !== '') {
      await dispatch(restoreSession());

      return;
    }

    dispatch(resetAuth());
  }
);
