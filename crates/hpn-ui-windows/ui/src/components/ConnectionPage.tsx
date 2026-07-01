import React, { useState } from 'react';
import { Power, CheckCircle2, XCircle, Loader2, ChevronDown, Lock, ShieldCheck, ArrowDown, ArrowUp } from 'lucide-react';
import { GlassCard, Button, Badge, cn } from './UIComponents';
import { ConnectionStatus, Profile } from '../types';
import { Translations } from '../i18n';

interface ConnectionPageProps {
  status: ConnectionStatus;
  profiles: Profile[];
  selectedProfileId: string | null;
  onConnect: () => void;
  onDisconnect: () => void;
  onSelectProfile: (id: string) => void;
  stats: {
    tx: number;
    rx: number;
    rtt: number;
    uptime: number;
    rate: number;
    session_id: string;
  };
  t: Translations;
  /** Used to immediately disable Connect button before React state updates */
  isConnecting?: boolean;
}

export const ConnectionPage: React.FC<ConnectionPageProps> = ({
  status,
  profiles,
  selectedProfileId,
  onConnect,
  onDisconnect,
  onSelectProfile,
  stats,
  t,
  isConnecting = false
}) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const selectedProfile = profiles.find(p => p.id === selectedProfileId);

  // Status visual logic
  const getStatusIcon = () => {
    switch (status) {
      case 'connected': return <Lock className="w-8 h-8 text-zinc-900 dark:text-white dark:drop-shadow-glow" />;
      case 'connecting': return <Loader2 className="w-8 h-8 text-zinc-400 animate-spin" />;
      case 'disconnecting': return <Loader2 className="w-8 h-8 text-zinc-400 animate-spin" />;
      case 'error': return <XCircle className="w-8 h-8 text-red-500" />;
      default: return <XCircle className="w-8 h-8 text-zinc-400 dark:text-zinc-600" />;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'connected': return "text-zinc-900 dark:text-white";
      case 'error': return "text-red-500";
      default: return "text-zinc-500 dark:text-zinc-400";
    }
  };

  const getStatusText = () => {
    return t.connection.status[status] || status;
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    return `${m}m ${s}s`;
  };

  return (
    <div className="flex flex-col h-full max-w-[480px] mx-auto space-y-5 py-4 px-2">

      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-white">{t.connection.title}</h1>
        {status === 'connected' && (
          <Badge variant="default" className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900/30">
            <ShieldCheck size={10} /> {t.connection.secure}
          </Badge>
        )}
      </div>

      {/* Profile Selector */}
      <div className="relative z-20">
        <GlassCard
          className="h-[42px] flex items-center justify-between px-4 cursor-pointer hover:bg-white dark:hover:bg-surface/80 hover:border-zinc-300 dark:hover:border-white/20"
          onClick={() => !menuOpen && setMenuOpen(true)}
        >
          <div className="flex items-center gap-2">
            <span className={cn("text-sm font-medium", selectedProfile ? "text-zinc-900 dark:text-zinc-100" : "text-zinc-500")}>
              {selectedProfile ? selectedProfile.name : t.connection.selectProfile}
            </span>
            {selectedProfile?.verified && <CheckCircle2 size={12} className="text-zinc-400" />}
          </div>
          <ChevronDown size={14} className="text-zinc-500" />
        </GlassCard>

        {menuOpen && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
            <div className="absolute top-[50px] left-0 w-full z-30 overflow-hidden rounded-xl border border-zinc-200 dark:border-white/10 bg-white dark:bg-[#0c0c0e] shadow-2xl animate-in fade-in slide-in-from-top-2 duration-200">
              <div className="max-h-[200px] overflow-y-auto py-1">
                {profiles.map(p => (
                  <button
                    key={p.id}
                    className="w-full text-left px-4 py-2.5 hover:bg-zinc-100 dark:hover:bg-white/5 transition-colors group"
                    onClick={() => {
                      onSelectProfile(p.id);
                      setMenuOpen(false);
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-zinc-700 dark:text-zinc-200 group-hover:text-zinc-900 dark:group-hover:text-white transition-colors">{p.name}</span>
                      {p.verified && <CheckCircle2 size={12} className="text-zinc-400 dark:text-zinc-500" />}
                    </div>
                    <div className="text-[10px] text-zinc-500 dark:text-zinc-600 font-mono truncate">{p.server}</div>
                  </button>
                ))}
                {profiles.length === 0 && (
                  <div className="px-4 py-3 text-sm text-zinc-500 text-center">{t.profiles.noProfiles}</div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Main Connection Status Card */}
      <GlassCard className="flex flex-col items-center justify-center p-8 min-h-[300px] relative overflow-hidden">
        {/* Animated Background Pulse for Connected State */}
        {status === 'connected' && (
          <div className="absolute inset-0 bg-red-500/5 animate-pulse pointer-events-none" />
        )}

        <div className="relative z-10 flex flex-col items-center gap-4 mb-16">
          <div className={cn(
            "w-20 h-20 rounded-full flex items-center justify-center border transition-all duration-500",
            status === 'connected'
              ? "bg-zinc-100 dark:bg-white/5 border-zinc-200 dark:border-white/20 dark:shadow-[0_0_30px_rgba(255,255,255,0.05)]"
              : "bg-zinc-50 dark:bg-black/20 border-zinc-200 dark:border-white/5"
          )}>
            {getStatusIcon()}
          </div>

          <div className="text-center space-y-1">
            <h2 className={cn("text-2xl font-semibold tracking-tight", getStatusColor())}>
              {getStatusText()}
            </h2>
            <p className="text-sm text-zinc-500 font-medium">
              {status === 'connected'
                ? `${t.connection.duration}: ${formatDuration(stats.uptime)}`
                : status === 'connecting'
                  ? t.connection.establishingTunnel
                  : status === 'disconnecting'
                    ? t.connection.closingTunnel
                    : t.connection.readyToConnect}
            </p>
          </div>
        </div>

        <div className="absolute bottom-6 w-full px-6">
           {status === 'connected' ? (
             <Button variant="danger" className="w-full h-11 text-base shadow-red-900/20" onClick={onDisconnect}>
               <Power className="w-4 h-4 mr-2" /> {t.connection.disconnect}
             </Button>
           ) : (
             <Button
                variant="primary"
                className="w-full h-11 text-base"
                onClick={onConnect}
                disabled={status !== 'disconnected' || !selectedProfile || isConnecting}
                isLoading={status === 'connecting' || isConnecting}
              >
               <Power className="w-4 h-4 mr-2" /> {(status === 'connecting' || isConnecting) ? t.connection.status.connecting : t.connection.connect}
             </Button>
           )}
        </div>
      </GlassCard>

      {/* Stats Grid (Only visible when connected) */}
      {status === 'connected' && (
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 space-y-4">

          <GlassCard className="p-4">
             <div className="grid grid-cols-2 gap-y-4 gap-x-8">
                <div className="space-y-1">
                   <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-600 font-semibold flex items-center gap-1">
                     <ArrowUp size={10} /> {t.connection.tx}
                   </div>
                   <div className="text-lg font-mono text-zinc-900 dark:text-zinc-200">{formatBytes(stats.tx)}</div>
                </div>
                <div className="space-y-1">
                   <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-600 font-semibold flex items-center gap-1">
                     <ArrowDown size={10} /> {t.connection.rx}
                   </div>
                   <div className="text-lg font-mono text-zinc-900 dark:text-zinc-200">{formatBytes(stats.rx)}</div>
                </div>
                <div className="space-y-1">
                   <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-600 font-semibold">{t.connection.latency}</div>
                   <div className="text-lg font-mono text-zinc-900 dark:text-zinc-200">{stats.rtt} ms</div>
                </div>
                <div className="space-y-1">
                   <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-600 font-semibold">{t.connection.sessionKey}</div>
                   <div className="text-lg font-mono text-zinc-900 dark:text-zinc-200 truncate w-full">
                     {status === 'connected' && stats.session_id ? `0x${stats.session_id.slice(0, 4).toUpperCase()}...${stats.session_id.slice(-2).toUpperCase()}` : '—'}
                   </div>
                </div>
             </div>
          </GlassCard>

          <GlassCard className="p-4 flex flex-col gap-2">
            <div className="flex justify-between items-end">
              <span className="text-xs text-zinc-500 font-medium">{t.connection.transferRate}</span>
              <span className="text-sm font-mono text-zinc-900 dark:text-white">{formatBytes(stats.rate)}/s</span>
            </div>
            {/* Custom Thin Progress Bar */}
            <div className="h-1 w-full bg-zinc-200 dark:bg-black/40 rounded-full overflow-hidden">
               {/* Simulating a visual bar based on arbitrary max of 10MB/s for demo */}
               <div
                  className="h-full bg-accent transition-all duration-300 ease-out"
                  style={{ width: `${Math.min((stats.rate / (1024 * 1024 * 10)) * 100, 100)}%` }}
               />
            </div>
          </GlassCard>

        </div>
      )}

      {/* Footer Crypto Info */}
      <div className="mt-auto pt-4 pb-2 text-center">
        <p className="text-[10px] font-mono text-zinc-500 dark:text-zinc-600 tracking-tight">
          {t.connection.cryptoInfo}
        </p>
      </div>

    </div>
  );
};
