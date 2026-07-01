import React, { ReactNode } from 'react';
import { Power, Users, FileText, Settings, Sun, Moon } from 'lucide-react';
import { cn } from './UIComponents';
import { TabId } from '../types';
import { Translations } from '../i18n';

interface AppShellProps {
  children: ReactNode;
  currentTab: TabId;
  onNavigate: (tab: TabId) => void;
  darkMode: boolean;
  onToggleTheme: () => void;
  currentLang: string;
  onToggleLang: () => void;
  t: Translations;
}

const FlagEN = () => (
  <svg viewBox="0 0 60 30" className="w-4 h-3 rounded-sm shadow-sm" xmlns="http://www.w3.org/2000/svg">
    <clipPath id="s">
      <path d="M0,0 v30 h60 v-30 z"/>
    </clipPath>
    <clipPath id="t">
      <path d="M30,15 h30 v15 z m0,0 v-15 h-30 z m0,0 h-30 v-15 z m0,0 v15 h30 z"/>
    </clipPath>
    <g clipPath="url(#s)">
      <path d="M0,0 v30 h60 v-30 z" fill="#012169"/>
      <path d="M0,0 L60,30 M60,0 L0,30" stroke="#fff" strokeWidth="6"/>
      <path d="M0,0 L60,30 M60,0 L0,30" clipPath="url(#t)" stroke="#C8102E" strokeWidth="4"/>
      <path d="M30,0 v30 M0,15 h60" stroke="#fff" strokeWidth="10"/>
      <path d="M30,0 v30 M0,15 h60" stroke="#C8102E" strokeWidth="6"/>
    </g>
  </svg>
);

const FlagFR = () => (
  <svg viewBox="0 0 3 2" className="w-4 h-3 rounded-sm shadow-sm" xmlns="http://www.w3.org/2000/svg">
    <rect width="3" height="2" fill="#ED2939"/>
    <rect width="2" height="2" fill="#fff"/>
    <rect width="1" height="2" fill="#002395"/>
  </svg>
);

export const AppShell: React.FC<AppShellProps> = ({
  children,
  currentTab,
  onNavigate,
  darkMode,
  onToggleTheme,
  currentLang,
  onToggleLang,
  t
}) => {

  const NavItem = ({ id, icon: Icon, label }: { id: TabId, icon: React.ElementType, label: string }) => {
    const isActive = currentTab === id;
    return (
      <button
        onClick={() => onNavigate(id)}
        className={cn(
          "flex-1 flex flex-col items-center justify-center gap-1.5 h-full transition-all duration-200 group relative",
          isActive ? "text-zinc-900 dark:text-white" : "text-zinc-400 dark:text-zinc-500 hover:text-zinc-600 dark:hover:text-zinc-300"
        )}
      >
        <div className={cn(
          "p-1.5 rounded-xl transition-all",
          isActive
            ? "bg-zinc-100 dark:bg-white/5"
            : "bg-transparent group-hover:bg-zinc-50 dark:group-hover:bg-white/5"
        )}>
          <Icon size={20} strokeWidth={isActive ? 2.5 : 2} className={cn(isActive && "dark:drop-shadow-[0_0_8px_rgba(255,255,255,0.3)]")} />
        </div>
        <span className="text-[10px] font-medium tracking-wide">{label}</span>

        {/* Active Indicator */}
        {isActive && (
          <div className="absolute top-0 w-8 h-[2px] bg-accent rounded-full shadow-[0_0_10px_#dc2626]" />
        )}
      </button>
    );
  };

  return (
    <div className="relative w-full h-full bg-zinc-50 dark:bg-background overflow-hidden flex flex-col select-none">

      {/* Top Utility Row (Chrome) */}
      <div className="h-10 px-6 flex items-center justify-between bg-white/60 dark:bg-black/40 backdrop-blur-md border-b border-zinc-200 dark:border-white/5 z-50">
        <div className="flex items-center gap-2">
          {/* Application Title */}
          <span className="text-xs font-bold text-zinc-600 dark:text-zinc-400 tracking-wider">HPN VPN</span>
          <span className="text-[10px] text-zinc-400 dark:text-zinc-700 ml-2">{t.common.version}</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onToggleLang}
            className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-zinc-100 dark:hover:bg-white/5 transition-colors text-xs text-zinc-600 dark:text-zinc-400 font-medium"
          >
            <span className="text-[10px] w-4 text-center">{currentLang}</span>
            {currentLang === 'EN' ? <FlagEN /> : <FlagFR />}
          </button>

          <button
            onClick={onToggleTheme}
            className="p-1.5 rounded-md text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-white/5 transition-colors"
          >
            {darkMode ? <Moon size={14} /> : <Sun size={14} />}
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className={cn(
        "flex-1 relative overflow-hidden",
        "bg-zinc-50 dark:bg-gradient-to-b dark:from-background dark:via-background dark:to-[#050505]"
      )}>
        {/* Ambient Glow Effects (Dark mode only) */}
        <div className="absolute top-[-20%] left-[20%] w-[400px] h-[400px] bg-accent/5 rounded-full blur-[100px] pointer-events-none opacity-0 dark:opacity-100" />

        <div className="relative z-10 h-full overflow-y-auto custom-scrollbar">
          {children}
        </div>
      </div>

      {/* Bottom Navigation */}
      <div className="h-[72px] bg-white/80 dark:bg-surface/80 backdrop-blur-xl border-t border-zinc-200 dark:border-white/5 px-6 flex items-center justify-between z-50">
        <div className="flex w-full max-w-[480px] mx-auto h-full pb-2 pt-1">
          <NavItem id="connection" icon={Power} label={t.nav.connection} />
          <NavItem id="profiles" icon={Users} label={t.nav.profiles} />
          <NavItem id="logs" icon={FileText} label={t.nav.logs} />
          <NavItem id="settings" icon={Settings} label={t.nav.settings} />
        </div>
      </div>

    </div>
  );
};
