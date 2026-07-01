import React, { useEffect, useRef } from 'react';
import { Download, FileText } from 'lucide-react';
import { GlassCard, Button } from './UIComponents';
import { LogEntry } from '../types';
import { Translations } from '../i18n';

interface LogsPageProps {
  logs: LogEntry[];
  onClear: () => void;
  onExport: () => void;
  t: Translations;
}

export const LogsPage: React.FC<LogsPageProps> = ({ logs, onClear, onExport, t }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Auto-scroll to bottom when new logs arrive
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="flex flex-col h-full max-w-[480px] mx-auto py-4 px-2">

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-white">{t.logs.title}</h1>
        <div className="flex items-center gap-2">
           <Button variant="outline" size="sm" onClick={onClear} className="h-7 text-xs px-3 border-zinc-300 dark:border-zinc-800 hover:border-zinc-400 dark:hover:border-zinc-700">
             {t.logs.clear}
           </Button>
           <Button variant="outline" size="sm" onClick={onExport} className="h-7 text-xs px-3 border-zinc-300 dark:border-zinc-800 hover:border-red-400 dark:hover:border-red-900/30 hover:text-red-500 dark:hover:text-red-400">
             <Download size={12} className="mr-1.5" /> {t.logs.export}
           </Button>
        </div>
      </div>

      {/* Console */}
      <GlassCard className="flex-1 overflow-hidden flex flex-col bg-zinc-950/5 dark:bg-[#0c0c0e]/80 border-zinc-300 dark:border-white/10">
        {logs.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 dark:text-zinc-700">
            <FileText size={32} strokeWidth={1} className="mb-2 opacity-50" />
            <p className="text-xs">{t.logs.noLogs}</p>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-3 space-y-1 font-mono text-[10px] sm:text-[11px] leading-tight">
            {logs.map((log) => {
              // Adapted colors for light/dark
              let colorClass = "text-zinc-600 dark:text-zinc-400"; // info
              if (log.level === 'warn') colorClass = "text-zinc-800 dark:text-zinc-200";
              if (log.level === 'error') colorClass = "text-red-600 dark:text-red-400";

              return (
                <div key={log.id} className="break-all whitespace-pre-wrap">
                  <span className="text-zinc-400 dark:text-zinc-600 mr-2 opacity-70">[{log.timestamp}]</span>
                  <span className={colorClass}>{log.message}</span>
                </div>
              );
            })}
            <div ref={bottomRef} />
          </div>
        )}
      </GlassCard>

    </div>
  );
};
