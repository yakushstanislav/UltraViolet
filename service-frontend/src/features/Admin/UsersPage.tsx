import { zodResolver } from '@hookform/resolvers/zod';
import * as Dialog from '@radix-ui/react-dialog';
import { isAxiosError } from 'axios';
import { Plus, Search, Trash2, Users, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

import { ConfirmDialog } from '@components/ConfirmDialog';
import { DialogSheetContent } from '@components/DialogSheetContent';
import { EmptyState } from '@components/EmptyState';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { Select } from '@components/Select';
import { SkeletonRow } from '@components/Skeleton';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { RoleSelect } from '@features/Admin/RoleSelect';
import { useAuthUserId } from '@features/Auth/hooks';
import { fieldAria, fieldErrorId } from '@helpers/formField';
import { formatDate, formatRelative } from '@helpers/format';
import { resolveAdminUserErrorMessage } from '@helpers/adminUserApiError';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { useDemoMode } from '@/hooks/useDemoMode';
import { useFocusFirstError } from '@/hooks/useFocusFirstError';
import {
  createUserSchema,
  type CreateUserFormValues,
  resetPasswordSchema,
  type ResetPasswordFormValues,
} from '@schemas/adminUser';
import {
  changeUserRole,
  createUser,
  listUsers,
  resetUserPassword,
  setUserActive,
} from '@services/UserAPI';
import type { AppRole, User } from '@/types/users';

import { UserAvatar } from './UserAvatar';
import { UserRowMenu } from './UserRowMenu';
import { UserStatusPill } from './UserStatusPill';

const ROLE_FILTERS: ReadonlyArray<'all' | AppRole> = [
  'all',
  'admin',
  'operator',
  'viewer',
];

const USERS_TABLE_SKELETON_ROWS: Array<
  Array<'short' | 'mid' | 'long'>
> = [
  ['long', 'mid', 'short', 'mid', 'short'],
  ['mid', 'mid', 'short', 'long', 'short'],
  ['long', 'mid', 'short', 'mid', 'short'],
  ['short', 'mid', 'short', 'long', 'short'],
  ['mid', 'mid', 'short', 'mid', 'short'],
  ['long', 'mid', 'short', 'long', 'short'],
];

const SEARCH_DEBOUNCE_MS = 250;

function parseRoleFilter(raw: string | null): AppRole | undefined {
  if (raw === 'admin' || raw === 'operator' || raw === 'viewer') {
    return raw;
  }
  return undefined;
}

function showAdminUserError(err: unknown, fallbackKey: string): void {
  toast.error(resolveAdminUserErrorMessage(err, fallbackKey));
}

export function UsersPage() {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const authUserId = useAuthUserId();
  const demoMode = useDemoMode();
  const [params, setParams] = useSearchParams();
  const [items, setItems] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshCount, setRefreshCount] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [disableConfirmUser, setDisableConfirmUser] = useState<User | null>(
    null
  );
  const [togglingUserId, setTogglingUserId] = useState<number | null>(null);

  const userCreateSchema = useMemo(() => createUserSchema(t), [t]);
  const userResetPasswordSchema = useMemo(() => resetPasswordSchema(t), [t]);

  const createForm = useForm<CreateUserFormValues>({
    resolver: zodResolver(userCreateSchema),
    defaultValues: { username: '', password: '', role: 'viewer' },
  });

  const resetForm = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(userResetPasswordSchema),
    defaultValues: { password: '' },
  });

  useFocusFirstError(
    createForm.formState.errors,
    createOpen && createForm.formState.isSubmitted
  );
  useFocusFirstError(
    resetForm.formState.errors,
    resetUser !== null && resetForm.formState.isSubmitted
  );

  useEffect(() => {
    if (!createOpen) {
      createForm.reset({ username: '', password: '', role: 'viewer' });
    }
  }, [createOpen, createForm]);

  useEffect(() => {
    resetForm.reset({ password: '' });
  }, [resetUser?.id, resetForm]);

  const page = parsePositiveInt(params.get('page'), 1);
  const limit = parsePositiveInt(params.get('limit'), 25);
  const qParam = params.get('q') ?? '';
  const roleParam = parseRoleFilter(params.get('role'));

  const [searchInput, setSearchInput] = useState(qParam);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(total / limit)),
    [limit, total]
  );

  useEffect(() => {
    if (loading || total === 0 || page <= totalPages) {
      return;
    }

    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('page', String(totalPages));
      next.set('limit', String(limit));
      return next;
    });
  }, [limit, loading, page, setParams, total, totalPages]);

  useEffect(() => {
    if (searchInput === qParam) {
      return;
    }

    const handle = window.setTimeout(() => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        if (searchInput === '') {
          next.delete('q');
        } else {
          next.set('q', searchInput);
        }
        next.set('page', '1');
        return next;
      });
    }, SEARCH_DEBOUNCE_MS);

    return () => {
      window.clearTimeout(handle);
    };
  }, [qParam, searchInput, setParams]);

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError('');

    void listUsers(page, limit, {
      q: qParam || undefined,
      role: roleParam,
    })
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        setItems(response.users ?? []);
        setTotal(response.total ?? 0);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        if (isAxiosError(err) && err.code === 'ERR_CANCELED') {
          return;
        }

        setError(err instanceof Error ? err.message : t('common.loadFailed'));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [page, limit, qParam, roleParam, refreshCount, t]);

  const hasActiveFilter = qParam !== '' || roleParam !== undefined;

  const setRoleFilter = (value: 'all' | AppRole) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === 'all') {
        next.delete('role');
      } else {
        next.set('role', value);
      }
      next.set('page', '1');
      return next;
    });
  };

  const clearFilters = () => {
    setSearchInput('');
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('q');
      next.delete('role');
      next.set('page', '1');
      return next;
    });
  };

  const applyActive = async (user: User, active: boolean) => {
    setTogglingUserId(user.id);

    try {
      const updated = await setUserActive(user.id, active);
      setItems((current) =>
        current.map((row) => (row.id === user.id ? updated : row))
      );
      toast.success(
        active ? t('adminUsers.enabled') : t('adminUsers.disabled')
      );
    } catch (err) {
      showAdminUserError(err, 'common.updateFailed');
    } finally {
      setTogglingUserId(null);
    }
  };

  const canDeactivate = (user: User): boolean => {
    if (authUserId !== null && user.id === authUserId && user.is_active) {
      return false;
    }

    return true;
  };

  const activeToggleTooltip = (user: User): string => {
    if (!user.is_active) {
      return t('adminUsers.enableUser');
    }

    if (!canDeactivate(user)) {
      return t('adminUsers.policyReasons.cannot_deactivate_self');
    }

    return t('adminUsers.disableUser');
  };

  const showToolbarCreate = !(isMobile && !loading && total === 0);

  const handleActiveToggle = (user: User) => {
    if (user.is_active) {
      if (!canDeactivate(user)) {
        toast.error(t('adminUsers.policyReasons.cannot_deactivate_self'));

        return;
      }

      setDisableConfirmUser(user);

      return;
    }

    void applyActive(user, true);
  };

  const handleCreate = async (values: CreateUserFormValues) => {
    try {
      await createUser(values);
      toast.success(t('adminUsers.created'));
      setCreateOpen(false);
      createForm.reset({ username: '', password: '', role: 'viewer' });
      setRefreshCount((c) => c + 1);
    } catch (err) {
      showAdminUserError(err, 'common.createFailed');
    }
  };

  const handleRoleChange = async (user: User, role: AppRole) => {
    try {
      const updated = await changeUserRole(user.id, role);
      setItems((current) =>
        current.map((row) => (row.id === user.id ? updated : row))
      );
      toast.success(t('adminUsers.roleUpdated'));
    } catch (err) {
      showAdminUserError(err, 'common.updateFailed');
    }
  };

  const commitDisable = async () => {
    if (!disableConfirmUser) {
      return;
    }

    await applyActive(disableConfirmUser, false);
  };

  const handleResetPassword = async (values: ResetPasswordFormValues) => {
    if (!resetUser) {
      return;
    }

    try {
      await resetUserPassword(resetUser.id, values.password);
      toast.success(t('adminUsers.passwordReset'));
      setResetUser(null);
      resetForm.reset({ password: '' });
    } catch (err) {
      showAdminUserError(err, 'common.updateFailed');
    }
  };

  return (
    <section className="page admin-users-page pagination-bar-scope">
      {error !== '' && <div className="error">{error}</div>}
      <div className="feature-page-stack">
        <div className="panel users-panel">
          <header className="users-header">
            <div className="users-header-title">
              <h2>
                <Users aria-hidden size={16} />
                {t('adminUsers.title')}
              </h2>
              <p className="panel-subtitle">{t('adminUsers.subtitle')}</p>
            </div>
          </header>
          <div className="users-toolbar">
            <div className="segmented-control" role="tablist">
              {ROLE_FILTERS.map((value) => {
                const active =
                  value === 'all'
                    ? roleParam === undefined
                    : roleParam === value;
                const label =
                  value === 'all'
                    ? t('adminUsers.roleFilterAll')
                    : t(`adminUsers.roleLabels.${value}`);
                return (
                  <button
                    aria-selected={active}
                    className={active ? 'segmented-active' : 'secondary'}
                    key={value}
                    onClick={() => setRoleFilter(value)}
                    role="tab"
                    type="button"
                  >
                    {label}
                  </button>
                );
              })}
            </div>
            <label className="users-search">
              <Search aria-hidden size={14} />
              <input
                autoComplete="off"
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder={t('adminUsers.searchPlaceholder')}
                type="search"
                value={searchInput}
              />
            </label>
            {hasActiveFilter && (
              <button
                className="secondary users-clear-filter"
                onClick={clearFilters}
                type="button"
              >
                <X aria-hidden size={14} />
                {t('adminUsers.clearFilter')}
              </button>
            )}
            {showToolbarCreate && (
              <button
                className="users-toolbar-cta"
                disabled={demoMode}
                onClick={() => setCreateOpen(true)}
                type="button"
              >
                <Plus aria-hidden size={16} />
                {t('adminUsers.newUser')}
              </button>
            )}
          </div>
          {isMobile ? (
            <UvCardList
              cardClassName={(user) =>
                user.is_active === false ? 'users-row-disabled' : ''
              }
              empty={
                total === 0 && !hasActiveFilter ? (
                  <EmptyState
                    action={
                      <button
                        disabled={demoMode}
                        onClick={() => setCreateOpen(true)}
                        type="button"
                      >
                        <Plus aria-hidden size={16} />
                        {t('adminUsers.newUser')}
                      </button>
                    }
                    hint={t('adminUsers.emptyHint')}
                    icon={<Users size={28} />}
                    title={t('adminUsers.emptyTitle')}
                  />
                ) : (
                  <div className="users-empty-filter">
                    {t('adminUsers.noFilterMatch')}
                  </div>
                )
              }
              getRowId={(user) => user.id}
              loading={loading}
              renderCard={(user) => {
                const isActive = user.is_active !== false;
                const isSelf =
                  authUserId !== null && user.id === authUserId;
                const canToggle =
                  togglingUserId !== user.id &&
                  (!isActive || canDeactivate(user));
                const lastSeen = user.last_login_at
                  ? t('adminUsers.lastSeen', {
                      when: formatRelative(user.last_login_at),
                    })
                  : t('adminUsers.lastSeenNever');

                return (
                  <>
                    <div className="uv-card__head">
                      <div className="user-cell">
                        <UserAvatar
                          role={user.role}
                          username={user.username}
                        />
                        <div className="user-cell-name uv-card__title">
                          <strong>{user.username}</strong>
                          {isSelf && (
                            <span className="user-cell-self">
                              {t('adminUsers.you')}
                            </span>
                          )}
                        </div>
                      </div>
                      <UserRowMenu
                        active={isActive}
                        canToggleActive={canToggle}
                        onResetPassword={() => setResetUser(user)}
                        onToggleActive={() => handleActiveToggle(user)}
                      />
                    </div>
                    <div className="uv-card__meta">
                      <RoleSelect
                        aria-label={t('adminUsers.roleFor', {
                          name: user.username,
                        })}
                        compact
                        disabled={isSelf}
                        onChange={(role) =>
                          void handleRoleChange(user, role)
                        }
                        value={user.role}
                      />
                      <UserStatusPill
                        activeLabel={t('adminUsers.statusActive')}
                        active={isActive}
                        ariaLabel={activeToggleTooltip(user)}
                        disabled={
                          togglingUserId === user.id ||
                          (isActive && !canDeactivate(user))
                        }
                        disabledLabel={t('adminUsers.statusDisabled')}
                        onClick={() => handleActiveToggle(user)}
                      />
                    </div>
                    <div className="uv-card__body">
                      <span
                        className={`users-activity-primary${
                          user.last_login_at
                            ? ''
                            : ' users-activity-never'
                        }`}
                      >
                        {lastSeen}
                      </span>
                      <span className="users-activity-muted">
                        {t('adminUsers.joined', {
                          when: formatRelative(user.created_at),
                        })}
                      </span>
                    </div>
                  </>
                );
              }}
              rows={items}
            />
          ) : (
            <div className="table-wrap pagination-scroll-anchor">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>{t('adminUsers.username')}</th>
                    <th className="users-role-col">{t('adminUsers.role')}</th>
                    <th className="users-status-col">
                      {t('adminUsers.active')}
                    </th>
                    <th className="users-activity-col">
                      {t('adminUsers.lastLogin')}
                    </th>
                    <th className="users-actions-col">
                      {t('columns.actions')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {loading &&
                    items.length === 0 &&
                    USERS_TABLE_SKELETON_ROWS.map((cells, index) => (
                      <SkeletonRow cells={cells} key={`sk-${index}`} />
                    ))}
                  {!loading && total === 0 && !hasActiveFilter && (
                    <tr>
                      <td className="table-empty-cell" colSpan={5}>
                        <EmptyState
                          action={
                            <button
                              onClick={() => setCreateOpen(true)}
                              type="button"
                            >
                              <Plus aria-hidden size={16} />
                              {t('adminUsers.newUser')}
                            </button>
                          }
                          hint={t('adminUsers.emptyHint')}
                          icon={<Users size={28} />}
                          title={t('adminUsers.emptyTitle')}
                        />
                      </td>
                    </tr>
                  )}
                  {!loading && total === 0 && hasActiveFilter && (
                    <tr>
                      <td className="table-empty-cell" colSpan={5}>
                        <div className="users-empty-filter">
                          {t('adminUsers.noFilterMatch')}
                        </div>
                      </td>
                    </tr>
                  )}
                  {!loading &&
                    items.map((user) => {
                      const isActive = user.is_active !== false;
                      const isSelf =
                        authUserId !== null && user.id === authUserId;
                      const canToggle =
                        togglingUserId !== user.id &&
                        (!isActive || canDeactivate(user));
                      const lastSeen = user.last_login_at
                        ? t('adminUsers.lastSeen', {
                            when: formatRelative(user.last_login_at),
                          })
                        : t('adminUsers.lastSeenNever');
                      const joined = t('adminUsers.joined', {
                        when: formatRelative(user.created_at),
                      });

                      return (
                        <tr
                          className={isActive ? '' : 'users-row-disabled'}
                          key={user.id}
                        >
                          <td>
                            <div className="user-cell">
                              <UserAvatar
                                role={user.role}
                                username={user.username}
                              />
                              <div className="user-cell-name">
                                <strong>{user.username}</strong>
                                {isSelf && (
                                  <span className="user-cell-self">
                                    {t('adminUsers.you')}
                                  </span>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="users-role-col">
                            <RoleSelect
                              aria-label={t('adminUsers.roleFor', {
                                name: user.username,
                              })}
                              compact
                              disabled={isSelf}
                              onChange={(role) =>
                                void handleRoleChange(user, role)
                              }
                              value={user.role}
                            />
                          </td>
                          <td className="users-status-col">
                            <Tooltip label={activeToggleTooltip(user)}>
                              <UserStatusPill
                                activeLabel={t('adminUsers.statusActive')}
                                active={isActive}
                                ariaLabel={activeToggleTooltip(user)}
                                disabled={
                                  togglingUserId === user.id ||
                                  (isActive && !canDeactivate(user))
                                }
                                disabledLabel={t('adminUsers.statusDisabled')}
                                onClick={() => handleActiveToggle(user)}
                              />
                            </Tooltip>
                          </td>
                          <td className="users-activity-col">
                            <div className="users-activity-cell">
                              <Tooltip
                                label={
                                  user.last_login_at
                                    ? formatDate(user.last_login_at)
                                    : t('adminUsers.lastSeenNever')
                                }
                              >
                                <span
                                  className={`users-activity-primary${
                                    user.last_login_at
                                      ? ''
                                      : ' users-activity-never'
                                  }`}
                                >
                                  {lastSeen}
                                </span>
                              </Tooltip>
                              <Tooltip label={formatDate(user.created_at)}>
                                <span className="users-activity-muted">
                                  {joined}
                                </span>
                              </Tooltip>
                            </div>
                          </td>
                          <td className="users-actions-col">
                            <UserRowMenu
                              active={isActive}
                              canToggleActive={canToggle}
                              onResetPassword={() => setResetUser(user)}
                              onToggleActive={() => handleActiveToggle(user)}
                            />
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <PaginationBarDock alignToScope>
          <div className="panel pagination-bar">
            <span className="pagination-bar-meta">
              {t('hostPage.paginationComma', {
                page,
                pages: totalPages,
                total,
              })}
            </span>
            <div className="header-actions pagination-bar-controls">
              <label className="muted-text pagination-bar-limit">
                {t('scansPage.limitLabel')}
                <Select
                  compact
                  onChange={(next) => {
                    const nextLimit = parsePositiveInt(next, 25);
                    setParams((prev) => {
                      const next = new URLSearchParams(prev);
                      next.set('page', '1');
                      next.set('limit', String(nextLimit));
                      return next;
                    });
                  }}
                  options={[25, 50, 100].map((value) => ({
                    label: String(value),
                    value: String(value),
                  }))}
                  value={String(limit)}
                />
              </label>
              <div className="pagination-bar-nav">
                <button
                  className="secondary"
                  disabled={page <= 1 || loading}
                  onClick={() => {
                    setParams((prev) => {
                      const next = new URLSearchParams(prev);
                      next.set('page', String(page - 1));
                      next.set('limit', String(limit));
                      return next;
                    });
                  }}
                  type="button"
                >
                  {t('common.prev')}
                </button>
                <button
                  className="secondary"
                  disabled={page >= totalPages || loading}
                  onClick={() => {
                    setParams((prev) => {
                      const next = new URLSearchParams(prev);
                      next.set('page', String(page + 1));
                      next.set('limit', String(limit));
                      return next;
                    });
                    requestAnimationFrame(() => scrollPaginationAnchor());
                  }}
                  type="button"
                >
                  {t('common.next')}
                </button>
              </div>
            </div>
          </div>
        </PaginationBarDock>
      </div>

      <ConfirmDialog
        confirmIcon={<Trash2 aria-hidden size={14} />}
        confirmLabel={t('adminUsers.disableConfirm')}
        description={
          disableConfirmUser
            ? t('adminUsers.disableDialogDescription', {
                name: disableConfirmUser.username,
              })
            : undefined
        }
        icon={<Trash2 aria-hidden size={20} />}
        onConfirm={commitDisable}
        onOpenChange={(open) => {
          if (!open) {
            setDisableConfirmUser(null);
          }
        }}
        open={disableConfirmUser !== null}
        title={t('adminUsers.disableDialogTitle')}
        tone="danger"
      />

      <Dialog.Root onOpenChange={setCreateOpen} open={createOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogSheetContent
            className="saved-search-dialog"
            onDismiss={() => setCreateOpen(false)}
          >
            <Dialog.Title>{t('adminUsers.dialogTitle')}</Dialog.Title>
            <form onSubmit={createForm.handleSubmit(handleCreate)}>
              <label className="search-field">
                <span className="search-field-label">
                  {t('adminUsers.username')}
                </span>
                <input
                  autoComplete="off"
                  className={
                    createForm.formState.errors.username
                      ? 'input-error'
                      : undefined
                  }
                  {...createForm.register('username')}
                  {...fieldAria(
                    'username',
                    Boolean(createForm.formState.errors.username)
                  )}
                />
                {createForm.formState.errors.username?.message && (
                  <span
                    className="field-error"
                    id={fieldErrorId('username')}
                    role="alert"
                  >
                    {createForm.formState.errors.username.message}
                  </span>
                )}
              </label>
              <label className="search-field">
                <span className="search-field-label">
                  {t('adminUsers.password')}
                </span>
                <input
                  autoComplete="new-password"
                  className={
                    createForm.formState.errors.password
                      ? 'input-error'
                      : undefined
                  }
                  type="password"
                  {...createForm.register('password')}
                  {...fieldAria(
                    'password',
                    Boolean(createForm.formState.errors.password)
                  )}
                />
                {createForm.formState.errors.password?.message && (
                  <span
                    className="field-error"
                    id={fieldErrorId('password')}
                    role="alert"
                  >
                    {createForm.formState.errors.password.message}
                  </span>
                )}
              </label>
              <label className="search-field">
                <span className="search-field-label">
                  {t('adminUsers.role')}
                </span>
                <RoleSelect
                  onChange={(role) =>
                    createForm.setValue('role', role, { shouldValidate: true })
                  }
                  value={createForm.watch('role')}
                />
              </label>
              <div className="dialog-actions">
                <Dialog.Close asChild>
                  <button className="secondary" type="button">
                    <X aria-hidden size={16} />
                    {t('common.cancel')}
                  </button>
                </Dialog.Close>
                <button type="submit">
                  <Plus aria-hidden size={16} />
                  {t('common.create')}
                </button>
              </div>
            </form>
          </DialogSheetContent>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root
        onOpenChange={(open) => {
          if (!open) {
            setResetUser(null);
          }
        }}
        open={resetUser !== null}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogSheetContent
            className="saved-search-dialog"
            onDismiss={() => {
              setResetUser(null);
            }}
          >
            <Dialog.Title>{t('adminUsers.resetDialogTitle')}</Dialog.Title>
            <form onSubmit={resetForm.handleSubmit(handleResetPassword)}>
              <label className="search-field">
                <span className="search-field-label">
                  {t('adminUsers.password')}
                </span>
                <input
                  autoComplete="new-password"
                  className={
                    resetForm.formState.errors.password
                      ? 'input-error'
                      : undefined
                  }
                  type="password"
                  {...resetForm.register('password')}
                  {...fieldAria(
                    'password',
                    Boolean(resetForm.formState.errors.password)
                  )}
                />
                {resetForm.formState.errors.password?.message && (
                  <span
                    className="field-error"
                    id={fieldErrorId('password')}
                    role="alert"
                  >
                    {resetForm.formState.errors.password.message}
                  </span>
                )}
              </label>
              <div className="dialog-actions">
                <Dialog.Close asChild>
                  <button className="secondary" type="button">
                    <X aria-hidden size={16} />
                    {t('common.cancel')}
                  </button>
                </Dialog.Close>
                <button type="submit">{t('adminUsers.resetPassword')}</button>
              </div>
            </form>
          </DialogSheetContent>
        </Dialog.Portal>
      </Dialog.Root>
    </section>
  );
}
