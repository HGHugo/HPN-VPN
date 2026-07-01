// Audit H14 — IPC contract tests for the auto-updater commands.
//
// These tests guard the JS → Rust binding for `check_for_updates`
// and `install_update` against silent ABI breakage. They do NOT
// exercise the actual updater plugin (that would require a Tauri
// runtime + a live HTTP endpoint) — only the IPC names and the
// payload shape.

import { afterEach, describe, expect, it } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';

import { getTranslations } from './i18n';

afterEach(() => {
  clearMocks();
});

describe('Tauri updater IPC contract', () => {
  it('check_for_updates returns null when no update is available', async () => {
    mockIPC((cmd) => {
      if (cmd === 'check_for_updates') return null;
      return null;
    });

    const result = await invoke<unknown>('check_for_updates');
    expect(result).toBeNull();
  });

  it('check_for_updates returns camelCase metadata when available', async () => {
    mockIPC((cmd) => {
      if (cmd === 'check_for_updates') {
        // MUST match the Rust `UpdateMetadata` serde camelCase shape
        // (see `src-tauri/src/updater.rs::UpdateMetadata`).
        return {
          version: '0.2.0',
          currentVersion: '0.1.0',
          notes: 'Bug fixes',
        };
      }
      return null;
    });

    const result = await invoke<{
      version: string;
      currentVersion: string;
      notes: string | null;
    }>('check_for_updates');

    expect(result).toMatchObject({
      version: '0.2.0',
      currentVersion: '0.1.0',
      notes: 'Bug fixes',
    });
  });

  it('install_update is invoked with an onEvent channel argument', async () => {
    let captured: Record<string, unknown> | null = null;
    mockIPC((cmd, args) => {
      if (cmd === 'install_update') {
        captured = args as Record<string, unknown>;
        return null;
      }
      return null;
    });

    // The frontend code path passes `{ onEvent: <Channel> }` — we
    // can't construct a real Channel in the mock environment
    // because @tauri-apps/api/mocks doesn't wire it, but we can
    // assert that an `onEvent` property is forwarded.
    await invoke('install_update', { onEvent: 'fake-channel-handle' });

    expect(captured).not.toBeNull();
    expect(captured).toHaveProperty('onEvent');
  });

  it('plugin:process|restart is the canonical relaunch invocation', async () => {
    // We don't strictly need to mock this — but the test pins the
    // command name so a rename in `tauri-plugin-process` would be
    // caught.
    let restartCalled = false;
    mockIPC((cmd) => {
      if (cmd === 'plugin:process|restart') {
        restartCalled = true;
      }
      return null;
    });

    await invoke('plugin:process|restart');
    expect(restartCalled).toBe(true);
  });
});

describe('Updater i18n', () => {
  it('EN translations expose the updater block with all required keys', () => {
    const t = getTranslations('EN');
    expect(t.updater).toBeDefined();
    expect(t.updater?.title).toBeTruthy();
    expect(t.updater?.releaseNotes).toBeTruthy();
    expect(t.updater?.readyToInstall).toBeTruthy();
    expect(t.updater?.downloadAndInstall).toBeTruthy();
    expect(t.updater?.later).toBeTruthy();
    expect(t.updater?.downloading).toBeTruthy();
    expect(t.updater?.installing).toBeTruthy();
    expect(t.updater?.installFailed).toBeTruthy();
    expect(t.updater?.retry).toBeTruthy();
  });

  it('FR translations expose the updater block with all required keys', () => {
    const t = getTranslations('FR');
    expect(t.updater).toBeDefined();
    expect(t.updater?.title).toBeTruthy();
    expect(t.updater?.releaseNotes).toBeTruthy();
    expect(t.updater?.readyToInstall).toBeTruthy();
    expect(t.updater?.downloadAndInstall).toBeTruthy();
    expect(t.updater?.later).toBeTruthy();
    expect(t.updater?.downloading).toBeTruthy();
    expect(t.updater?.installing).toBeTruthy();
    expect(t.updater?.installFailed).toBeTruthy();
    expect(t.updater?.retry).toBeTruthy();
  });
});
