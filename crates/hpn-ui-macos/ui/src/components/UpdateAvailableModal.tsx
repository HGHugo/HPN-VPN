// Audit H14 (auto-update at launch) — modal that listens for the
// `update-available` event emitted by the Rust setup task and walks
// the user through the download + install + restart flow.
//
// Lifecycle:
//   1. Component mounts on App.tsx render; registers Tauri event
//      listener for `update-available`.
//   2. Rust setup task fires `update-available` ~3 s after launch
//      if the configured updater endpoint returns 200.
//   3. Listener sets local state → modal renders with metadata.
//   4. User clicks "Download & Install":
//      - phase: 'downloading' — invokes `install_update` with a
//        Channel for progress events (Started / Progress / Finished).
//      - phase: 'installing' — after Finished, invokes
//        `plugin:process|restart` (macOS) or lets the running
//        process exit (Windows installer takes over).
//   5. User clicks "Later" → modal dismisses for this launch. Next
//      launch re-checks (auto-check is mount-only, runs on every
//      app start).
//
// Error handling: any failure during install surfaces as 'error'
// phase with a retry button. We log to console for debugging but
// avoid global toasts — the modal is the only consumer of these
// events.

import React, { useEffect, useState } from 'react';
import { invoke, Channel } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { Download, X, RefreshCw, AlertCircle } from 'lucide-react';

import { GlassCard, Button } from './UIComponents';
import { Translations } from '../i18n';

interface UpdateMetadata {
  version: string;
  currentVersion: string;
  notes: string | null;
}

// Mirror of Rust `updater::DownloadEvent` (see
// `src-tauri/src/updater.rs`). The serde tag/content shape MUST
// match what the backend emits over the Tauri Channel.
type DownloadEvent =
  | { event: 'Started'; data: { contentLength: number | null } }
  | { event: 'Progress'; data: { chunkLength: number } }
  | { event: 'Finished' };

type ModalPhase = 'available' | 'downloading' | 'installing' | 'error';

interface Props {
  t: Translations;
}

const formatBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
};

const formatError = (e: unknown): string => {
  if (typeof e === 'string') return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === 'object' && 'message' in e) {
    return String((e as { message: unknown }).message);
  }
  try {
    return JSON.stringify(e);
  } catch {
    return 'Unknown error';
  }
};

export const UpdateAvailableModal: React.FC<Props> = ({ t }) => {
  const [update, setUpdate] = useState<UpdateMetadata | null>(null);
  const [phase, setPhase] = useState<ModalPhase>('available');
  const [downloaded, setDownloaded] = useState(0);
  const [total, setTotal] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Register the Tauri event listener exactly once per mount.
  // The Rust side fires `update-available` ~3 s after launch.
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;

    listen<UpdateMetadata>('update-available', (event) => {
      // eslint-disable-next-line no-console
      console.log('[updater] update available:', event.payload);
      setUpdate(event.payload);
      setPhase('available');
      setDownloaded(0);
      setTotal(null);
      setErrorMsg(null);
    })
      .then((fn) => {
        if (cancelled) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch((e: unknown) => {
        // eslint-disable-next-line no-console
        console.error('[updater] failed to register listener:', e);
      });

    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  const handleLater = () => {
    // Dismiss for this launch only. Auto-check runs again next time
    // the app is started, so the user will see the popup again
    // unless they install the update or pick "Later" repeatedly.
    setUpdate(null);
  };

  const handleInstall = async () => {
    if (!update) return;
    setPhase('downloading');
    setErrorMsg(null);
    setDownloaded(0);
    setTotal(null);

    const channel = new Channel<DownloadEvent>();
    channel.onmessage = (msg) => {
      if (msg.event === 'Started') {
        setTotal(msg.data.contentLength);
      } else if (msg.event === 'Progress') {
        setDownloaded((prev) => prev + msg.data.chunkLength);
      } else if (msg.event === 'Finished') {
        // Visual transition to "installing" — relaunch happens AFTER
        // `install_update` resolves, see below.
        setPhase('installing');
      }
    };

    try {
      // Per Tauri docs, the canonical pattern is:
      //   await update.downloadAndInstall();
      //   await relaunch();
      //
      // On Windows, `install_update` NEVER resolves: the running
      // process is killed by the MSI installer takeover before the
      // promise can complete (documented limitation). The `await`
      // below therefore blocks forever, the lines after it are
      // unreachable on Windows, and the new install replaces the
      // binary which is then re-launched manually by the user via
      // their Start menu shortcut.
      //
      // On macOS, `install_update` extracts the new `.app.tar.gz`
      // bundle in place and returns. We then invoke
      // `plugin:process|restart` to swap the running process to
      // the new binary, completing the transparent update flow.
      await invoke('install_update', { onEvent: channel });
      await invoke('plugin:process|restart');
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[updater] install failed:', e);
      setErrorMsg(formatError(e));
      setPhase('error');
    }
  };

  if (!update) return null;

  // i18n fallback: if the `updater` block is missing (older
  // translation file deployed alongside a newer binary), bail out
  // rather than render with raw key names.
  const u = t.updater;
  if (!u) return null;

  const progress = total ? Math.min(100, (downloaded / total) * 100) : 0;
  const isBusy = phase === 'downloading' || phase === 'installing';

  return (
    <div className="absolute inset-0 z-[55] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <GlassCard className="w-full max-w-[420px] flex flex-col bg-white dark:bg-zinc-950 border-zinc-200 dark:border-white/10 shadow-2xl animate-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-100 dark:border-white/5">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-full bg-accent/10 dark:bg-accent/20">
              <Download className="w-5 h-5 text-accent" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-900 dark:text-white">{u.title}</h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                v{update.currentVersion}{' '}
                <span className="text-zinc-400 dark:text-zinc-600">→</span>{' '}
                <span className="text-accent font-medium">v{update.version}</span>
              </p>
            </div>
          </div>
          {!isBusy && (
            <Button variant="ghost" size="icon" onClick={handleLater}>
              <X className="w-5 h-5" />
            </Button>
          )}
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {phase === 'error' && errorMsg && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50">
              <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="text-sm text-red-600 dark:text-red-400 font-medium">
                  {u.installFailed}
                </p>
                <p className="text-xs text-red-500/80 dark:text-red-400/80 mt-1 break-words">
                  {errorMsg}
                </p>
              </div>
            </div>
          )}

          {phase === 'available' && update.notes && (
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                {u.releaseNotes}
              </p>
              <pre className="text-xs text-zinc-600 dark:text-zinc-300 whitespace-pre-wrap font-sans max-h-40 overflow-y-auto p-3 rounded-lg bg-zinc-50 dark:bg-black/30 border border-zinc-100 dark:border-white/5">
                {update.notes}
              </pre>
            </div>
          )}

          {phase === 'available' && !update.notes && (
            <p className="text-sm text-zinc-500 dark:text-zinc-400">{u.readyToInstall}</p>
          )}

          {isBusy && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-500 dark:text-zinc-400">
                  {phase === 'installing' ? u.installing : u.downloading}
                </span>
                {phase === 'downloading' && total !== null && (
                  <span className="text-zinc-500 dark:text-zinc-400 font-mono">
                    {formatBytes(downloaded)} / {formatBytes(total)}
                  </span>
                )}
              </div>
              <div className="h-1.5 bg-zinc-100 dark:bg-zinc-800 rounded-full overflow-hidden">
                {phase === 'downloading' && total !== null ? (
                  <div
                    className="h-full bg-accent transition-all duration-100 ease-linear"
                    style={{ width: `${progress}%` }}
                  />
                ) : (
                  // Indeterminate: either downloading without
                  // Content-Length, or installing/restarting.
                  <div className="h-full w-1/3 bg-accent/60 animate-pulse" />
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        {!isBusy && (
          <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-zinc-100 dark:border-white/5 bg-zinc-50/50 dark:bg-black/20">
            <Button variant="ghost" onClick={handleLater}>
              {u.later}
            </Button>
            <Button variant="primary" onClick={handleInstall}>
              {phase === 'error' ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  {u.retry}
                </>
              ) : (
                <>
                  <Download className="w-4 h-4 mr-2" />
                  {u.downloadAndInstall}
                </>
              )}
            </Button>
          </div>
        )}
      </GlassCard>
    </div>
  );
};
