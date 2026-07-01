import React, { useState, useCallback } from 'react';
import { X, User, Lock, AlertCircle } from 'lucide-react';
import { GlassCard, Button, Input, cn } from './UIComponents';
import { Profile } from '../types';
import { Translations } from '../i18n';

interface LoginModalProps {
  profile: Profile;
  onSubmit: (username: string, password: string) => void;
  onCancel: () => void;
  isLoading?: boolean;
  error?: string;
  t: Translations;
}

export const LoginModal: React.FC<LoginModalProps> = ({
  profile,
  onSubmit,
  onCancel,
  isLoading = false,
  error,
  t
}) => {
  // Pre-fill username from profile if saved
  const [username, setUsername] = useState(profile.username || '');
  const [password, setPassword] = useState('');
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (username.trim() && password) {
      onSubmit(username.trim(), password);
    } else {
      setTouched({ username: true, password: true });
    }
  }, [username, password, onSubmit]);

  const getUsernameError = (): string | undefined => {
    if (!touched.username) return undefined;
    if (!username.trim()) return t.auth?.usernameRequired || 'Username is required';
    return undefined;
  };

  const getPasswordError = (): string | undefined => {
    if (!touched.password) return undefined;
    if (!password) return t.auth?.passwordRequired || 'Password is required';
    return undefined;
  };

  const isValid = username.trim() && password;

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/60 backdrop-blur-sm">
      <GlassCard className="w-full max-w-[380px] flex flex-col bg-white dark:bg-zinc-950 border-zinc-200 dark:border-white/10 shadow-2xl animate-in zoom-in-95 duration-200">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-100 dark:border-white/5">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-full bg-accent/10 dark:bg-accent/20">
              <Lock className="w-5 h-5 text-accent" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
                {t.auth?.title || 'Authentication Required'}
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">{profile.name}</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onCancel} disabled={isLoading}>
            <X className="w-5 h-5" />
          </Button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          
          {/* Error Display */}
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50">
              <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0" />
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          {/* Username Field */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
              {t.auth?.username || 'Username'}
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
              <Input
                type="text"
                placeholder={t.auth?.usernamePlaceholder || 'Enter your username'}
                value={username}
                onChange={e => setUsername(e.target.value)}
                onBlur={() => setTouched(prev => ({ ...prev, username: true }))}
                className={cn("pl-10", getUsernameError() ? 'border-red-500 dark:border-red-500' : '')}
                disabled={isLoading}
                autoFocus
                autoComplete="username"
              />
            </div>
            {getUsernameError() && (
              <div className="flex items-center gap-1 text-xs text-red-500">
                <AlertCircle size={12} />
                <span>{getUsernameError()}</span>
              </div>
            )}
          </div>

          {/* Password Field */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
              {t.auth?.password || 'Password'}
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
              <Input
                type="password"
                placeholder={t.auth?.passwordPlaceholder || 'Enter your password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                onBlur={() => setTouched(prev => ({ ...prev, password: true }))}
                className={cn("pl-10", getPasswordError() ? 'border-red-500 dark:border-red-500' : '')}
                disabled={isLoading}
                autoComplete="current-password"
              />
            </div>
            {getPasswordError() && (
              <div className="flex items-center gap-1 text-xs text-red-500">
                <AlertCircle size={12} />
                <span>{getPasswordError()}</span>
              </div>
            )}
          </div>

          {/* Info text */}
          <p className="text-[10px] text-zinc-400 dark:text-zinc-600">
            {t.auth?.passwordNotStored || 'Your password is never stored locally and is encrypted before transmission.'}
          </p>
        </form>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-zinc-100 dark:border-white/5 bg-zinc-50/50 dark:bg-black/20">
          <Button variant="ghost" onClick={onCancel} disabled={isLoading}>
            {t.editor.cancel}
          </Button>
          <Button
            type="submit"
            variant="primary"
            onClick={handleSubmit}
            disabled={!isValid || isLoading}
            isLoading={isLoading}
          >
            {isLoading ? (
              <>{t.auth?.authenticating || 'Authenticating...'}</>
            ) : (
              <>{t.auth?.connect || 'Connect'}</>
            )}
          </Button>
        </div>

      </GlassCard>
    </div>
  );
};
