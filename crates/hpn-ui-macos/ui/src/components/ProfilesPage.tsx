import React from 'react';
import { Plus, Users, RefreshCw, CheckCircle2, Trash2, Edit } from 'lucide-react';
import { GlassCard, Button, Badge } from './UIComponents';
import { Profile } from '../types';
import { Translations } from '../i18n';

interface ProfilesPageProps {
  profiles: Profile[];
  onRefresh: () => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
  onCreate: () => void;
  t: Translations;
}

export const ProfilesPage: React.FC<ProfilesPageProps> = ({ profiles, onRefresh, onEdit, onDelete, onCreate, t }) => {
  return (
    <div className="flex flex-col h-full max-w-[480px] mx-auto py-4 px-2">

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-white">{t.profiles.title}</h1>
        <div className="flex items-center gap-2">
           <Button variant="ghost" size="icon" onClick={onRefresh} className="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-white">
             <RefreshCw size={16} />
           </Button>
           <Button variant="primary" size="sm" onClick={onCreate} className="h-8 rounded-full px-4 text-xs">
             <Plus size={14} className="mr-1.5" /> {t.profiles.new}
           </Button>
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto space-y-3 pb-4">
        {profiles.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-zinc-400 dark:text-zinc-600">
            <Users size={48} strokeWidth={1} className="mb-4 opacity-50" />
            <p className="text-sm">{t.profiles.noProfiles}</p>
          </div>
        ) : (
          profiles.map((profile) => (
            <GlassCard key={profile.id} className="p-4 flex items-center justify-between group hover:border-zinc-300 dark:hover:border-white/20">
               <div className="flex flex-col gap-1 overflow-hidden">
                 <div className="flex items-center gap-2">
                   <span className="font-medium text-sm text-zinc-900 dark:text-zinc-100 truncate">{profile.name}</span>
                   {profile.verified && (
                     <CheckCircle2 size={12} className="text-zinc-400 dark:text-zinc-500 shrink-0" />
                   )}
                   {profile.splitTunnel?.enabled && (
                     <Badge variant="outline" className="text-[9px] h-4 py-0 px-1 border-zinc-300 dark:border-white/5 text-zinc-500">
                       {t.profiles.split}
                     </Badge>
                   )}
                 </div>
                 <span className="text-[11px] text-zinc-500 font-mono truncate">{profile.server}:{profile.port}</span>
               </div>

               <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                 <Button variant="ghost" size="icon" onClick={() => onEdit(profile.id)} className="h-8 w-8 hover:bg-zinc-100 dark:hover:bg-white/5">
                   <Edit size={14} />
                 </Button>
                 <Button variant="ghost" size="icon" onClick={() => onDelete(profile.id)} className="h-8 w-8 text-zinc-400 hover:text-red-600 dark:text-zinc-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10">
                   <Trash2 size={14} />
                 </Button>
               </div>
            </GlassCard>
          ))
        )}
      </div>

    </div>
  );
};
