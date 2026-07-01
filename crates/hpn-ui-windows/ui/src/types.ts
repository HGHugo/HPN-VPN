export type TabId = 'connection' | 'profiles' | 'logs' | 'settings';

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'reconnecting' | 'error';

export type SecurityLevel = 'standard' | 'high';

export interface Profile {
  id: string;
  name: string;
  server: string;
  port: number;
  serverPublicKey: string;
  verified?: boolean;
  securityLevel?: SecurityLevel; // standard = ML-KEM-768/ML-DSA-65, high = ML-KEM-1024/ML-DSA-87
  serverKemPublicKey?: string; // Base64-encoded server KEM public key for identity hiding
  requiresAuth?: boolean; // Whether server requires user authentication
  username?: string; // Stored username (password entered at connect time)
  splitTunnel?: {
    enabled: boolean;
    mode: 'full' | 'bypass';
    routes?: string;
    bypassLocal?: boolean;
    bypassDiscovery?: boolean;
  };
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error';
  message: string;
}

// Settings interface matching backend Settings struct (camelCase via serde)
export interface AppSettings {
  darkMode: boolean;
  autoReconnect: boolean;
  killSwitch: boolean; // Always true, cannot be disabled
  autoRekey: boolean;
  language: string; // "EN" or "FR"
  keepaliveInterval: number; // seconds
  connectionTimeout: number; // seconds
}

export interface AppState {
  currentTab: TabId;
  status: ConnectionStatus;
  selectedProfileId: string | null;
  profiles: Profile[];
  logs: LogEntry[];
  settings: AppSettings;
  stats: {
    tx: number; // bytes
    rx: number; // bytes
    rtt: number; // ms
    uptime: number; // seconds
    rate: number; // bytes per second
    session_id: string; // hex session ID
  };
}
