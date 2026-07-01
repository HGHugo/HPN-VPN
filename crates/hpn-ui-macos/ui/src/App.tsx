import React, { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';

import { AppShell } from './components/AppShell';
import { ConnectionPage } from './components/ConnectionPage';
import { ProfilesPage } from './components/ProfilesPage';
import { LogsPage } from './components/LogsPage';
import { SettingsPage } from './components/SettingsPage';
import { ProfileEditor } from './components/ProfileEditor';
import { LoginModal } from './components/LoginModal';
import { UpdateAvailableModal } from './components/UpdateAvailableModal';
import { ToastContainer, useToasts, ConfirmDialog } from './components/UIComponents';
import { AppState, AppSettings, Profile, LogEntry } from './types';
import { Language, getTranslations } from './i18n';

// --- Tauri Backend Types ---

// Backend get_status returns the enum directly as a string, not an object
type TauriConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'reconnecting' | 'error';

const formatTauriError = (error: unknown): string => {
  if (typeof error === 'string') return error;
  if (error instanceof Error && error.message) return error.message;

  if (error && typeof error === 'object') {
    const record = error as Record<string, unknown>;
    const candidates = [record.message, record.error, record.details, record.reason];

    for (const candidate of candidates) {
      if (typeof candidate === 'string' && candidate.trim()) {
        return candidate;
      }
      if (candidate && typeof candidate === 'object') {
        const nested = formatTauriError(candidate);
        if (nested !== 'Unknown error') {
          return nested;
        }
      }
    }

    try {
      return JSON.stringify(error);
    } catch {
      return 'Unknown error';
    }
  }

  return 'Unknown error';
};



const App: React.FC = () => {
  // --- State ---
  const [currentTab, setCurrentTab] = useState<AppState['currentTab']>('connection');
  const [status, setStatus] = useState<AppState['status']>('disconnected');
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // Toast notifications system
  const { toasts, addToast, removeToast } = useToasts();

  // Connection in progress flag (prevents double-clicks more reliably than status)
  const [isConnecting, setIsConnecting] = useState(false);
  // Atomic ref to prevent race conditions with React state batching
  const connectingRef = useRef(false);
  const backendLogCountRef = useRef(0);

  // Settings State (must match backend Settings struct)
  const [settings, setSettings] = useState<AppSettings>({
    darkMode: true,
    autoReconnect: true,
    killSwitch: true,
    autoRekey: true,
    language: 'EN',
    keepaliveInterval: 25,
    connectionTimeout: 30
  });

  // Stats State
  const [stats, setStats] = useState({
    tx: 0,
    rx: 0,
    rtt: 0,
    uptime: 0,
    rate: 0,
    session_id: ''
  });

  // UI State
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editorMode, setEditorMode] = useState<'create' | 'edit'>('create');
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [currentLang, setCurrentLang] = useState<Language>('EN');
  const [deleteConfirm, setDeleteConfirm] = useState<{ isOpen: boolean; profileId: string | null }>({ isOpen: false, profileId: null });

  // Authentication modal state
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [authError, setAuthError] = useState<string | undefined>(undefined);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  // Get translations
  const t = getTranslations(currentLang);

  // --- Theme Effect (apply dark mode on mount and when changed) ---
  useEffect(() => {
    // Apply dark mode immediately on mount
    document.documentElement.classList.add('dark');
  }, []);

  useEffect(() => {
    if (settings.darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [settings.darkMode]);

  // --- Helpers ---

  const addLog = useCallback((level: LogEntry['level'], message: string) => {
    const newLog: LogEntry = {
      id: Math.random().toString(36).substring(7),
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      level,
      message
    };
    setLogs(prev => [...prev, newLog]);
  }, []);

  // --- Load settings and profiles from backend ---

  useEffect(() => {
    const loadInitialData = async () => {
      try {
        // Load profiles from backend
        const savedProfiles = await invoke<Profile[]>('get_profiles').catch((err) => {
          console.error('Failed to load profiles:', err);
          return null;
        });
        if (savedProfiles && savedProfiles.length > 0) {
          setProfiles(savedProfiles);
          setSelectedProfileId(savedProfiles[0].id);
        }

        // Load settings from backend
        const savedSettings = await invoke<AppSettings>('get_settings').catch((err) => {
          console.error('Failed to load settings:', err);
          return null;
        });
        if (savedSettings) {
          setSettings(savedSettings);
        }

        // Get current connection status (returns enum directly as string)
        const currentStatus = await invoke<TauriConnectionStatus>('get_status').catch((err) => {
          console.error('Failed to get status:', err);
          return null;
        });
        if (currentStatus) {
          setStatus(currentStatus);
        }
      } catch (e) {
        console.error('Failed to load initial data:', e);
      }
    };

    loadInitialData();
  }, []);

  // --- Polling for status, stats and logs ---

  useEffect(() => {
    // Poll status, logs, and stats during active states
    const shouldPoll = status === 'connected' || status === 'connecting' ||
                       status === 'disconnecting' || status === 'reconnecting' ||
                       status === 'error';
    if (!shouldPoll) return;

    const pollInterval = setInterval(async () => {
      try {
        // ALWAYS poll status to stay in sync with backend
        const currentStatus = await invoke<TauriConnectionStatus>('get_status');
        if (currentStatus !== status) {
          setStatus(currentStatus);

          // Reset connecting flag when we reach a final state
          if (currentStatus === 'connected' || currentStatus === 'disconnected' || currentStatus === 'error') {
            connectingRef.current = false;
            setIsConnecting(false);
          }

          // On error, show error toast and reset to disconnected after a moment
          if (currentStatus === 'error') {
            addToast('Connection failed. Check credentials and try again.', 'error', {
              title: 'VPN Error',
              duration: 8000
            });
            // Reset to disconnected so the user can retry
            setTimeout(() => setStatus('disconnected'), 2000);
          }

          // Show success toast on connection
          if (currentStatus === 'connected' && status === 'connecting') {
            addToast('VPN tunnel established successfully', 'success', {
              title: 'Connected',
              duration: 5000
            });
          }
        }

        // Poll stats only when connected
        if (currentStatus === 'connected') {
          const currentStats = await invoke<{
            tx: number;
            rx: number;
            rtt: number;
            uptime: number;
            rate: number;
            session_id: string;
          }>('get_stats');
          setStats(currentStats);
        }

        // Poll logs from backend (track backend count separately to avoid
        // skipping logs when frontend adds its own entries via addLog)
        const backendLogs = await invoke<LogEntry[]>('get_logs');
        if (backendLogs.length > backendLogCountRef.current) {
          const newLogs = backendLogs.slice(backendLogCountRef.current);
          backendLogCountRef.current = backendLogs.length;
          setLogs(prev => [...prev, ...newLogs]);
        }
      } catch (e) {
        console.error('Polling error:', e);
      }
    }, 500); // Poll every 500ms for more responsive status updates

    return () => clearInterval(pollInterval);
  }, [status, addToast]);

  // --- Connection Handlers ---

  const handleConnect = async () => {
    // Atomic check using ref to prevent race conditions with React batching
    if (connectingRef.current) {
      return;
    }
    // Also check state as a secondary measure
    if (isConnecting) {
      return;
    }
    // Also check status as a safety measure
    if (status !== 'disconnected' && status !== 'error') {
      return;
    }
    if (!selectedProfileId) {
      addToast('Please select a profile first', 'warning', { title: 'No Profile' });
      return;
    }
    const profile = profiles.find(p => p.id === selectedProfileId);
    if (!profile) {
      addToast('Selected profile not found', 'error', { title: 'Error' });
      return;
    }

    // Check if profile requires authentication
    if (profile.requiresAuth) {
      // Show login modal instead of connecting directly
      setAuthError(undefined);
      setShowLoginModal(true);
      return;
    }

    // Profile doesn't require auth, connect directly
    await performConnect(selectedProfileId);
  };

  // Internal function to perform the actual connection
  const performConnect = async (profileId: string, credentials?: { username: string; password: string }) => {
    const profile = profiles.find(p => p.id === profileId);
    if (!profile) {
      addToast('Selected profile not found', 'error', { title: 'Error' });
      return;
    }

    // Set connecting state atomically FIRST via ref, then state
    connectingRef.current = true;
    setIsConnecting(true);
    setStatus('connecting');
    addLog('info', `Initializing handshake with ${profile.server}...`);


    // Set up frontend connection timeout as a fallback.
    // Add 5 seconds buffer to let the backend's timeout trigger first,
    // since the backend provides more detailed error messages.
    const backendTimeoutSecs = settings.connectionTimeout || 30;
    const frontendTimeoutMs = (backendTimeoutSecs + 5) * 1000;
    const timeoutId = setTimeout(() => {
      // Frontend connection timeout reached (backend may have hung)
      connectingRef.current = false;
      setIsConnecting(false);
      setStatus('disconnected');
      setIsAuthenticating(false);
      addToast(
        `Server did not respond within ${backendTimeoutSecs + 5} seconds`,
        'error',
        { title: 'Connection Timeout', duration: 10000 }
      );
      addLog('error', `Connection timeout after ${backendTimeoutSecs + 5}s (frontend fallback)`);
    }, frontendTimeoutMs);

    try {
      if (credentials) {
        // Connect with authentication
        await invoke('connect_with_auth', { 
          profileId, 
          username: credentials.username, 
          password: credentials.password 
        });
      } else {
        // Connect without authentication
        await invoke('connect', { profileId });
      }
      clearTimeout(timeoutId);
      // Status will be updated via event listener
      // Close login modal on success
      setShowLoginModal(false);
      setIsAuthenticating(false);
    } catch (e) {
      clearTimeout(timeoutId);
      connectingRef.current = false;
      setIsConnecting(false);
      setStatus('disconnected');
      setIsAuthenticating(false);
      const errorMsg = formatTauriError(e);
      
      // If this was an auth attempt, show error in modal
      if (credentials) {
        setAuthError(errorMsg);
      } else {
        setShowLoginModal(false);
        addToast(errorMsg, 'error', { title: 'Connection Failed', duration: 10000 });
      }
      addLog('error', `Connection failed: ${errorMsg}`);
    }
  };

  // Handle login modal submission
  const handleAuthSubmit = async (username: string, password: string) => {
    if (!selectedProfileId) return;
    
    setIsAuthenticating(true);
    setAuthError(undefined);
    await performConnect(selectedProfileId, { username, password });
  };

  // Handle login modal cancel
  const handleAuthCancel = () => {
    setShowLoginModal(false);
    setAuthError(undefined);
    setIsAuthenticating(false);
  };

  const handleDisconnect = async () => {
    setStatus('disconnecting');
    addLog('info', 'Terminating session...');

    try {
      await invoke('disconnect');
      addToast('VPN disconnected', 'info', { duration: 3000 });
    } catch (e) {
      const errorMsg = formatTauriError(e);
      addToast(errorMsg, 'error', { title: 'Disconnect Failed' });
      addLog('error', `Disconnect failed: ${errorMsg}`);
      setStatus('disconnected');
    }
  };

  // --- Profile Management ---

  const openCreateProfile = () => {
    setEditorMode('create');
    setEditingProfileId(null);
    setIsEditorOpen(true);
  };

  const openEditProfile = (id: string) => {
    setEditorMode('edit');
    setEditingProfileId(id);
    setIsEditorOpen(true);
  };

  const handleDeleteProfile = (id: string) => {
    setDeleteConfirm({ isOpen: true, profileId: id });
  };

  const confirmDeleteProfile = async () => {
    const id = deleteConfirm.profileId;
    setDeleteConfirm({ isOpen: false, profileId: null });
    if (!id) return;
    try {
      await invoke('delete_profile', { profileId: id });
      setProfiles(prev => prev.filter(p => p.id !== id));
      if (selectedProfileId === id) setSelectedProfileId(null);
      addLog('info', `Profile deleted.`);
    } catch (e) {
      addLog('error', `Failed to delete profile: ${formatTauriError(e)}`);
    }
  };

  const handleProfileSubmit = async (profileData: Omit<Profile, 'id'>) => {
    try {
      if (editorMode === 'create') {
        const newProfile = await invoke<Profile>('save_profile', { profile: profileData });
        setProfiles([...profiles, newProfile]);
        addLog('info', `Created profile: ${newProfile.name}`);
      } else if (editorMode === 'edit' && editingProfileId) {
        const updatedProfile = await invoke<Profile>('save_profile', {
          profile: { ...profileData, id: editingProfileId }
        });
        setProfiles(profiles.map(p => p.id === editingProfileId ? updatedProfile : p));
        addLog('info', `Updated profile: ${profileData.name}`);
      }
      setIsEditorOpen(false);
    } catch (e) {
      const errorMsg = formatTauriError(e);
      addToast(errorMsg, 'error', { title: 'Profile Save Failed', duration: 10000 });
      addLog('error', `Failed to save profile: ${errorMsg}`);
    }
  };

  const handleRefreshProfiles = async () => {
    addLog('info', 'Refreshing profiles...');
    try {
      const refreshedProfiles = await invoke<Profile[]>('get_profiles');
      setProfiles(refreshedProfiles);
      // If current selection is no longer valid, select first profile
      if (refreshedProfiles.length > 0) {
        const currentStillExists = refreshedProfiles.some(p => p.id === selectedProfileId);
        if (!currentStillExists) {
          setSelectedProfileId(refreshedProfiles[0].id);
        }
      } else {
        setSelectedProfileId(null);
      }
      addLog('info', `Loaded ${refreshedProfiles.length} profile(s)`);
    } catch (e) {
      addLog('error', `Failed to refresh profiles: ${formatTauriError(e)}`);
    }
  };

  // --- Settings Handlers ---

  const handleToggleSetting = async (key: keyof AppSettings) => {
    if (key === 'killSwitch') return; // Kill switch cannot be disabled

    // Only toggle boolean settings
    if (typeof settings[key] !== 'boolean') return;

    const newSettings = { ...settings, [key]: !settings[key] };
    setSettings(newSettings);

    try {
      await invoke('save_settings', { settings: newSettings });
    } catch (e) {
      addLog('error', `Failed to save settings: ${formatTauriError(e)}`);
    }
  };

  const handleForceRekey = async () => {
    addLog('info', 'Forcing immediate key rotation...');
    try {
      await invoke('force_rekey');
      addLog('info', 'Key rotation initiated.');
    } catch (e) {
      addLog('error', `Re-key failed: ${formatTauriError(e)}`);
    }
  };

  // --- Log Handlers ---

  const handleExportLogs = async () => {
    try {
      const exportPath = await invoke<string>('export_logs');
      addLog('info', `Logs exported to: ${exportPath}`);
    } catch (e) {
      addLog('error', `Failed to export logs: ${formatTauriError(e)}`);
    }
  };

  // --- Language Toggle ---

  const handleToggleLang = () => {
    setCurrentLang(l => l === 'EN' ? 'FR' : 'EN');
  };

  // --- Render ---

  return (
    <AppShell
      currentTab={currentTab}
      onNavigate={setCurrentTab}
      darkMode={settings.darkMode}
      onToggleTheme={() => handleToggleSetting('darkMode')}
      currentLang={currentLang}
      onToggleLang={handleToggleLang}
      t={t}
    >
      {/* Page Routing */}

      {currentTab === 'connection' && (
        <ConnectionPage
          status={status}
          profiles={profiles}
          selectedProfileId={selectedProfileId}
          onSelectProfile={setSelectedProfileId}
          onConnect={handleConnect}
          onDisconnect={handleDisconnect}
          stats={stats}
          t={t}
          isConnecting={isConnecting}
        />
      )}

      {currentTab === 'profiles' && (
        <ProfilesPage
          profiles={profiles}
          onRefresh={handleRefreshProfiles}
          onCreate={openCreateProfile}
          onEdit={openEditProfile}
          onDelete={handleDeleteProfile}
          t={t}
        />
      )}

      {currentTab === 'logs' && (
        <LogsPage
          logs={logs}
          onClear={() => { setLogs([]); invoke('clear_logs').catch(() => {}); }}
          onExport={handleExportLogs}
          t={t}
        />
      )}

      {currentTab === 'settings' && (
        <SettingsPage
          settings={settings}
          isConnected={status === 'connected'}
          onToggleSetting={handleToggleSetting}
          onForceRekey={handleForceRekey}
          t={t}
        />
      )}

      {/* Overlays */}

      {isEditorOpen && (
        <ProfileEditor
          mode={editorMode}
          initialValues={editorMode === 'edit' ? profiles.find(p => p.id === editingProfileId) : undefined}
          onCancel={() => setIsEditorOpen(false)}
          onSubmit={handleProfileSubmit}
          t={t}
        />
      )}

      {/* Login Modal for authenticated profiles */}
      {showLoginModal && selectedProfileId && profiles.find(p => p.id === selectedProfileId) && (
        <LoginModal
          profile={profiles.find(p => p.id === selectedProfileId)!}
          onSubmit={handleAuthSubmit}
          onCancel={handleAuthCancel}
          isLoading={isAuthenticating}
          error={authError}
          t={t}
        />
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={deleteConfirm.isOpen}
        title={t.profiles.deleteTitle || 'Delete Profile'}
        message={t.profiles.deleteConfirm}
        confirmLabel={t.profiles.deleteButton || 'Delete'}
        cancelLabel={t.editor?.cancel || 'Cancel'}
        variant="danger"
        onConfirm={confirmDeleteProfile}
        onCancel={() => setDeleteConfirm({ isOpen: false, profileId: null })}
      />

      {/* Auto-Update Modal (audit H14).
          Self-contained: listens for the `update-available` event
          emitted by the Rust setup task 3s after launch. Renders
          nothing until an update is detected. */}
      <UpdateAvailableModal t={t} />

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onClose={removeToast} position="bottom" />

    </AppShell>
  );
};

export default App;
