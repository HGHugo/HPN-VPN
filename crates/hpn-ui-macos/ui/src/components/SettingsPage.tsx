import React from 'react';
import { Key, ShieldAlert } from 'lucide-react';
import { GlassCard, Switch, Button } from './UIComponents';
import { AppSettings } from '../types';
import { Translations } from '../i18n';

interface SettingsPageProps {
  settings: AppSettings;
  isConnected: boolean;
  onToggleSetting: (key: keyof AppSettings) => void;
  onForceRekey: () => void;
  t: Translations;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({ settings, isConnected, onToggleSetting, onForceRekey, t }) => {
  return (
    <div className="flex flex-col h-full max-w-[420px] mx-auto py-4 px-2 space-y-5">

      {/* Header */}
      <div className="flex items-center gap-2 mb-1">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-white">{t.settings.title}</h1>
      </div>

      {/* Card 1: Appearance & Connection */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider pl-1">{t.settings.appearanceConnection}</h3>
        <GlassCard className="flex flex-col divide-y divide-zinc-100 dark:divide-white/5">

          <div className="flex items-center justify-between p-4">
            <div className="flex flex-col gap-0.5">
               <span className="text-sm font-medium text-zinc-900 dark:text-zinc-200">{t.settings.darkTheme}</span>
               <span className="text-[11px] text-zinc-500">{t.settings.darkThemeDesc}</span>
            </div>
            <Switch checked={settings.darkMode} onCheckedChange={() => onToggleSetting('darkMode')} />
          </div>

          <div className="flex items-center justify-between p-4">
            <div className="flex flex-col gap-0.5">
               <span className="text-sm font-medium text-zinc-900 dark:text-zinc-200">{t.settings.autoReconnect}</span>
               <span className="text-[11px] text-zinc-500">{t.settings.autoReconnectDesc}</span>
            </div>
            <Switch checked={settings.autoReconnect} onCheckedChange={() => onToggleSetting('autoReconnect')} />
          </div>

          <div className="flex items-center justify-between p-4 bg-red-50 dark:bg-red-500/5">
            <div className="flex flex-col gap-0.5">
               <span className="text-sm font-medium text-red-600 dark:text-red-200">{t.settings.killSwitch}</span>
               <span className="text-[11px] text-red-500/70">{t.settings.killSwitchDesc}</span>
            </div>
            <Switch checked={true} disabled />
          </div>

        </GlassCard>
      </div>

      {/* Card 2: Cryptography */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider pl-1">{t.settings.cryptography}</h3>
        <GlassCard className="flex flex-col divide-y divide-zinc-100 dark:divide-white/5">

           <div className="flex items-center justify-between p-4">
            <div className="flex flex-col gap-0.5">
               <span className="text-sm font-medium text-zinc-900 dark:text-zinc-200">{t.settings.autoRekey}</span>
               <span className="text-[11px] text-zinc-500">{t.settings.autoRekeyDesc}</span>
            </div>
            <Switch checked={settings.autoRekey} onCheckedChange={() => onToggleSetting('autoRekey')} />
          </div>

          <div className="p-4">
            <Button
              variant="outline"
              className={isConnected ? "w-full border-red-500/30 text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10" : "w-full opacity-50"}
              disabled={!isConnected}
              onClick={onForceRekey}
            >
              <Key size={14} className="mr-2" /> {t.settings.forceRekey}
            </Button>
            {!isConnected && (
              <p className="text-[10px] text-zinc-400 dark:text-zinc-600 mt-2 text-center">{t.settings.forceRekeyDisabled}</p>
            )}
          </div>

        </GlassCard>
      </div>

      {/* Card: Privacy & Leak Protection (advisory) */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider pl-1">{t.settings.privacy}</h3>
        <GlassCard className="flex flex-col divide-y divide-zinc-100 dark:divide-white/5">

          {/* WebRTC leak — advisory only, the VPN cannot block this without a browser extension */}
          <div className="flex flex-col gap-1.5 p-4">
            <div className="flex items-center gap-2">
              <ShieldAlert size={14} className="text-amber-500" />
              <span className="text-sm font-medium text-zinc-900 dark:text-zinc-200">
                {t.settings.webrtcLeak}
              </span>
            </div>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
              {t.settings.webrtcLeakDesc}
            </p>
            <ul className="list-disc pl-5 space-y-0.5 text-[10px] text-zinc-500 dark:text-zinc-500">
              <li>{t.settings.webrtcChromeHowto}</li>
              <li>{t.settings.webrtcFirefoxHowto}</li>
            </ul>
          </div>

          {/* DNS leak — informational, VPN already enforces this */}
          <div className="flex flex-col gap-1 p-4">
            <span className="text-sm font-medium text-zinc-900 dark:text-zinc-200">
              {t.settings.dnsLeak}
            </span>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
              {t.settings.dnsLeakDesc}
            </p>
          </div>

        </GlassCard>
      </div>

      {/* Card 3: App Info */}
      <GlassCard className="p-4 mt-4 bg-transparent border-dashed border-zinc-300 dark:border-zinc-800 shadow-none">
        <div className="text-center space-y-1">
          <p className="text-[11px] text-zinc-400 dark:text-zinc-500">{t.settings.appVersion}</p>
          <p className="text-[10px] text-zinc-500 dark:text-zinc-700 font-mono whitespace-pre-line">
            {t.settings.cryptoDetails}
          </p>
        </div>
      </GlassCard>

    </div>
  );
};
