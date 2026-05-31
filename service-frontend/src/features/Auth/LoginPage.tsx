import { zodResolver } from '@hookform/resolvers/zod';
import { Eye, EyeOff, Loader2, Lock, Moon, Sun, User } from 'lucide-react';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation } from 'react-router-dom';

import { loginUser } from './authSlice';
import { LoginRadarBackground } from './LoginRadarBackground';
import { BrandMark } from '@components/BrandMark';
import { FieldLabel } from '@components/FieldLabel';
import { fieldAria, fieldErrorId } from '@helpers/formField';
import { useFocusFirstError } from '@/hooks/useFocusFirstError';
import { createLoginSchema, type LoginFormValues } from '@schemas/login';
import { useAppDispatch, useAppSelector } from '@store/store';
import { useTheme } from '@/theme/ThemeProvider';

type NavigationState = {
  from?: {
    pathname: string;
  };
};

const SHAKE_DURATION_MS = 420;

function sanitizeRedirectPath(raw: string | undefined): string {
  if (!raw || typeof raw !== 'string') {
    return '/';
  }

  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return '/';
  }

  return raw;
}

export function LoginPage() {
  const { t } = useTranslation();
  const dispatch = useAppDispatch();
  const { role, loading, error } = useAppSelector((state) => state.auth);
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const state = location.state as NavigationState | null;
  const redirectTo = sanitizeRedirectPath(state?.from?.pathname);

  const loginSchema = useMemo(() => createLoginSchema(t), [t]);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitted },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: '', password: '' },
  });

  useFocusFirstError(errors, isSubmitted);

  const [showPassword, setShowPassword] = useState(false);
  const [capsLockOn, setCapsLockOn] = useState(false);
  const [errorFlash, setErrorFlash] = useState(false);
  const shakeTimerRef = useRef<number | null>(null);

  const usernameRef = useRef<HTMLInputElement | null>(null);
  const usernameReg = register('username');

  useEffect(() => {
    if (role === null) {
      usernameRef.current?.focus();
    }
  }, [role]);

  useEffect(() => {
    const previous = document.title;
    document.title = t('auth.documentTitle');

    return () => {
      document.title = previous;
    };
  }, [t]);

  useEffect(() => {
    return () => {
      if (shakeTimerRef.current !== null) {
        window.clearTimeout(shakeTimerRef.current);
      }
    };
  }, []);

  const triggerShake = useCallback(() => {
    if (shakeTimerRef.current !== null) {
      window.clearTimeout(shakeTimerRef.current);
    }

    setErrorFlash(false);
    window.requestAnimationFrame(() => {
      setErrorFlash(true);
      shakeTimerRef.current = window.setTimeout(() => {
        setErrorFlash(false);
        shakeTimerRef.current = null;
      }, SHAKE_DURATION_MS);
    });
  }, []);

  if (role !== null) {
    return <Navigate replace to={redirectTo} />;
  }

  const onSubmit = handleSubmit(
    async (values) => {
      const result = await dispatch(loginUser(values));

      if (loginUser.rejected.match(result)) {
        triggerShake();
      }
    },
    () => {
      triggerShake();
    },
  );

  const handlePasswordKey = (event: KeyboardEvent<HTMLInputElement>) => {
    setCapsLockOn(event.getModifierState('CapsLock'));
  };

  const authError =
    isSubmitted &&
    error !== null &&
    error !== '' &&
    errors.username === undefined &&
    errors.password === undefined
      ? error
      : null;

  const isDark = theme === 'dark';
  const themeToggleLabel = t(
    isDark ? 'auth.themeToggleToLight' : 'auth.themeToggleToDark',
  );
  const versionLabel = t('auth.versionLabel', { version: __APP_VERSION__ });

  return (
    <section className="login-page">
      <LoginRadarBackground />
      <div className="login-card">
        <header className="login-card-header">
          <BrandMark className="login-mark" size={72} />
          <div className="login-card-heading">
            <p className="login-card-eyebrow">{t('auth.loginEyebrow')}</p>
            <h1>
              {t('auth.loginTitle')}
              <span className="cli-cursor" />
            </h1>
            <p className="login-card-tagline">{t('auth.loginTagline')}</p>
          </div>
        </header>
        <form
          aria-label={t('auth.loginFormAria')}
          className={errorFlash ? 'is-error-flash' : undefined}
          onSubmit={onSubmit}
        >
          <label>
            <FieldLabel required>{t('auth.username')}</FieldLabel>
            <div className="login-input-wrap">
              <User className="login-input-icon" size={16} aria-hidden />
              <input
                autoComplete="username"
                placeholder={t('auth.usernamePlaceholder')}
                required
                aria-required="true"
                {...usernameReg}
                ref={(element) => {
                  usernameReg.ref(element);
                  usernameRef.current = element;
                }}
                className={errors.username ? 'input-error' : undefined}
                {...fieldAria('username', Boolean(errors.username))}
              />
            </div>
            {errors.username && (
              <span
                className="field-error"
                id={fieldErrorId('username')}
                role="alert"
              >
                {errors.username.message}
              </span>
            )}
          </label>
          <label>
            <FieldLabel required>{t('auth.password')}</FieldLabel>
            <div className="login-password-wrap">
              <div className="login-input-wrap">
                <Lock className="login-input-icon" size={16} aria-hidden />
                <input
                  autoComplete="current-password"
                  placeholder={t('auth.passwordPlaceholder')}
                  required
                  aria-required="true"
                  type={showPassword ? 'text' : 'password'}
                  onKeyDown={handlePasswordKey}
                  onKeyUp={handlePasswordKey}
                  {...register('password')}
                  className={errors.password ? 'input-error' : undefined}
                  {...fieldAria('password', Boolean(errors.password))}
                />
              </div>
              <button
                type="button"
                className="login-password-toggle"
                aria-label={t(
                  showPassword ? 'auth.hidePassword' : 'auth.showPassword',
                )}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((value) => !value)}
              >
                {showPassword ? (
                  <EyeOff size={16} aria-hidden />
                ) : (
                  <Eye size={16} aria-hidden />
                )}
              </button>
            </div>
            {capsLockOn && !errors.password && (
              <span className="login-caps-hint" role="status">
                {t('auth.capsLockOn')}
              </span>
            )}
            {errors.password && (
              <span
                className="field-error"
                id={fieldErrorId('password')}
                role="alert"
              >
                {errors.password.message}
              </span>
            )}
          </label>
          {authError !== null && (
            <div className="login-error-pill" role="alert" aria-live="polite">
              <span className="login-error-dot" aria-hidden />
              <span>{authError}</span>
            </div>
          )}
          <button aria-busy={loading} disabled={loading} type="submit">
            {loading ? (
              <>
                <Loader2 className="spin" size={16} aria-hidden />
                {t('auth.signingIn')}
              </>
            ) : (
              t('auth.signIn')
            )}
          </button>
        </form>
      </div>
      <footer className="login-footer">
        <button
          type="button"
          className="login-theme-toggle"
          aria-label={themeToggleLabel}
          aria-pressed={isDark}
          onClick={toggleTheme}
        >
          {isDark ? (
            <Sun size={14} aria-hidden />
          ) : (
            <Moon size={14} aria-hidden />
          )}
        </button>
        <span className="login-version" aria-label={versionLabel}>
          {versionLabel}
        </span>
      </footer>
    </section>
  );
}
