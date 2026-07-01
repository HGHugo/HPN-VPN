import React, { useState, useMemo } from 'react';
import { X, Globe, Split, Eye, EyeOff, AlertCircle, Shield, ShieldCheck, User, Lock } from 'lucide-react';
import { GlassCard, Button, Input, Switch, SegmentedControl } from './UIComponents';
import { Profile, SecurityLevel } from '../types';
import { Translations } from '../i18n';

// Validation utilities
const isValidHostname = (hostname: string): boolean => {
  if (!hostname || hostname.length > 253) return false;
  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(hostname)) return true;
  // IPv6 (simplified - brackets optional)
  const ipv6Regex = /^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$/;
  if (ipv6Regex.test(hostname)) return true;
  // Hostname (RFC 1123)
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return hostnameRegex.test(hostname);
};

const isValidPort = (port: string): boolean => {
  const num = parseInt(port, 10);
  return !isNaN(num) && num >= 1 && num <= 65535;
};

const isValidBase64PublicKey = (key: string): boolean => {
  if (!key) return false;
  // ML-KEM-768 public key is 1184 bytes = 1579 base64 chars (with padding)
  // ML-KEM-1024 public key is 1568 bytes = 2092 base64 chars
  // X25519 public key is 32 bytes = 44 base64 chars
  // We accept hybrid keys which may be concatenated
  const base64Regex = /^[A-Za-z0-9+/]+=*$/;
  if (!base64Regex.test(key)) return false;
  // Minimum 32 bytes (X25519), reasonable max ~4KB for hybrid
  const decoded = key.replace(/=/g, '');
  const bytes = (decoded.length * 3) / 4;
  return bytes >= 32 && bytes <= 4096;
};

const isValidCIDR = (cidr: string): boolean => {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return false;
  const [ip, prefix] = parts;
  const prefixNum = parseInt(prefix, 10);

  // IPv4 CIDR. Prefix MUST be >= 1: `0.0.0.0/0` would attempt to
  // exclude the entire IPv4 internet, defeating the tunnel. The Rust
  // validator (routing.rs::parse_cidr) accepts /0 silently and would
  // install a route covering 0.0.0.0/0 via the physical interface,
  // i.e. a complete tunnel bypass. We reject it in the UI so the user
  // gets immediate feedback instead of the leak.
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(ip)) {
    return !isNaN(prefixNum) && prefixNum >= 1 && prefixNum <= 32;
  }

  // IPv6 CIDR. Same fail-closed reasoning for `::/0`.
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(ip)) {
    return !isNaN(prefixNum) && prefixNum >= 1 && prefixNum <= 128;
  }

  return false;
};

const validateRoutes = (routes: string): { valid: boolean; invalidRoutes: string[] } => {
  if (!routes.trim()) return { valid: true, invalidRoutes: [] };
  const routeList = routes.split(',').map(r => r.trim()).filter(r => r);
  const invalidRoutes = routeList.filter(r => !isValidCIDR(r));
  return { valid: invalidRoutes.length === 0, invalidRoutes };
};

interface ValidationError {
  field: string;
  message: string;
}

interface ProfileEditorProps {
  mode: 'create' | 'edit';
  initialValues?: Partial<Profile>;
  onCancel: () => void;
  onSubmit: (profile: Omit<Profile, 'id'>) => void;
  t: Translations;
}

export const ProfileEditor: React.FC<ProfileEditorProps> = ({ mode, initialValues, onCancel, onSubmit, t }) => {
  const [name, setName] = useState(initialValues?.name || '');
  const [server, setServer] = useState(initialValues?.server || '');
  const [port, setPort] = useState(initialValues?.port?.toString() || '51820');
  const [serverPublicKey, setServerPublicKey] = useState(initialValues?.serverPublicKey || '');
  const [serverKemPublicKey, setServerKemPublicKey] = useState(initialValues?.serverKemPublicKey || '');
  const [showKey, setShowKey] = useState(false);
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  // Security level state
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>(initialValues?.securityLevel || 'standard');

  // Authentication state
  const [requiresAuth, setRequiresAuth] = useState(initialValues?.requiresAuth ?? false);
  const [username, setProfileUsername] = useState(initialValues?.username || '');

  // Split tunneling state
  const [tunnelMode, setTunnelMode] = useState<'full' | 'bypass'>(initialValues?.splitTunnel?.mode || 'full');
  const [routes, setRoutes] = useState(initialValues?.splitTunnel?.routes || '');
  const [bypassLocal, setBypassLocal] = useState(initialValues?.splitTunnel?.bypassLocal ?? true);
  const [bypassDiscovery, setBypassDiscovery] = useState(initialValues?.splitTunnel?.bypassDiscovery ?? true);

  // Validation
  const errors = useMemo((): ValidationError[] => {
    const errs: ValidationError[] = [];
    
    if (name.trim().length === 0) {
      errs.push({ field: 'name', message: t.validation?.nameRequired || 'Profile name is required' });
    } else if (name.length > 100) {
      errs.push({ field: 'name', message: t.validation?.nameTooLong || 'Profile name must be 100 characters or less' });
    }
    
    if (!isValidHostname(server)) {
      errs.push({ field: 'server', message: t.validation?.invalidServer || 'Invalid server address (hostname or IP)' });
    }
    
    if (!isValidPort(port)) {
      errs.push({ field: 'port', message: t.validation?.invalidPort || 'Port must be between 1 and 65535' });
    }
    
    if (!isValidBase64PublicKey(serverPublicKey)) {
      errs.push({ field: 'serverPublicKey', message: t.validation?.invalidPublicKey || 'Invalid public key format (base64)' });
    }

    if (serverKemPublicKey && !isValidBase64PublicKey(serverKemPublicKey)) {
      errs.push({ field: 'serverKemPublicKey', message: t.validation?.invalidKemPublicKey || 'Invalid KEM public key format (base64)' });
    }

    if (requiresAuth && !serverKemPublicKey.trim()) {
      errs.push({
        field: 'serverKemPublicKey',
        message: t.editor.serverKemPublicKeyDesc || 'Server KEM public key is required when authentication is enabled'
      });
    }
    
    if (tunnelMode === 'bypass' && routes.trim()) {
      const routeValidation = validateRoutes(routes);
      if (!routeValidation.valid) {
        errs.push({ 
          field: 'routes', 
          message: `${t.validation?.invalidRoutes || 'Invalid CIDR routes'}: ${routeValidation.invalidRoutes.join(', ')}` 
        });
      }
    }
    
    return errs;
  }, [name, server, port, serverPublicKey, serverKemPublicKey, requiresAuth, routes, tunnelMode, t]);

  const getFieldError = (field: string): string | undefined => {
    if (!touched[field]) return undefined;
    return errors.find(e => e.field === field)?.message;
  };

  const markTouched = (field: string) => {
    setTouched(prev => ({ ...prev, [field]: true }));
  };

  const isFormValid = errors.length === 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Mark all fields as touched to show validation errors
    setTouched({
      name: true,
      server: true,
      port: true,
      serverPublicKey: true,
      serverKemPublicKey: true,
      routes: true
    });
    
    if (!isFormValid) return;
    
    onSubmit({
      name,
      server,
      port: parseInt(port, 10) || 51820,
      serverPublicKey,
      serverKemPublicKey: serverKemPublicKey || undefined,
      verified: initialValues?.verified || false,
      securityLevel,
      requiresAuth,
      username: requiresAuth ? username || undefined : undefined,
      splitTunnel: {
        enabled: tunnelMode === 'bypass',
        mode: tunnelMode,
        routes: tunnelMode === 'bypass' ? routes : undefined,
        bypassLocal: tunnelMode === 'bypass' ? bypassLocal : undefined,
        bypassDiscovery: tunnelMode === 'bypass' ? bypassDiscovery : undefined
      }
    });
  };

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/60 backdrop-blur-sm">
      <GlassCard className="w-full max-w-[480px] h-[85%] max-h-[640px] flex flex-col bg-white dark:bg-zinc-950 border-zinc-200 dark:border-white/10 shadow-2xl animate-in zoom-in-95 duration-200">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-100 dark:border-white/5">
          <h2 className="text-lg font-semibold text-zinc-900 dark:text-white">
            {mode === 'create' ? t.editor.newProfile : t.editor.editProfile}
          </h2>
          <Button variant="ghost" size="icon" onClick={onCancel}>
            <X className="w-5 h-5" />
          </Button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <form id="profile-form" onSubmit={handleSubmit} className="space-y-4">

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{t.editor.profileName}</label>
              <Input
                placeholder={t.editor.profileNamePlaceholder}
                value={name}
                onChange={e => setName(e.target.value)}
                onBlur={() => markTouched('name')}
                className={getFieldError('name') ? 'border-red-500 dark:border-red-500' : ''}
                autoFocus
              />
              {getFieldError('name') && (
                <div className="flex items-center gap-1 text-xs text-red-500">
                  <AlertCircle size={12} />
                  <span>{getFieldError('name')}</span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2 space-y-1.5">
                <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{t.editor.serverAddress}</label>
                <Input
                  placeholder={t.editor.serverPlaceholder}
                  value={server}
                  onChange={e => setServer(e.target.value)}
                  onBlur={() => markTouched('server')}
                  className={getFieldError('server') ? 'border-red-500 dark:border-red-500' : ''}
                />
                {getFieldError('server') && (
                  <div className="flex items-center gap-1 text-xs text-red-500">
                    <AlertCircle size={12} />
                    <span>{getFieldError('server')}</span>
                  </div>
                )}
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{t.editor.port}</label>
                <Input
                  placeholder="51820"
                  value={port}
                  onChange={e => setPort(e.target.value)}
                  onBlur={() => markTouched('port')}
                  className={getFieldError('port') ? 'border-red-500 dark:border-red-500' : ''}
                />
                {getFieldError('port') && (
                  <div className="flex items-center gap-1 text-xs text-red-500">
                    <AlertCircle size={12} />
                    <span>{getFieldError('port')}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{t.editor.serverPublicKey}</label>
              <div className="relative">
                <Input
                  type={showKey ? "text" : "password"}
                  placeholder={t.editor.serverPublicKeyPlaceholder}
                  value={serverPublicKey}
                  onChange={e => setServerPublicKey(e.target.value)}
                  onBlur={() => markTouched('serverPublicKey')}
                  className={`pr-10 font-mono text-xs ${getFieldError('serverPublicKey') ? 'border-red-500 dark:border-red-500' : ''}`}
                />
                <button
                  type="button"
                  onClick={() => setShowKey(!showKey)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"
                >
                  {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              {getFieldError('serverPublicKey') && (
                <div className="flex items-center gap-1 text-xs text-red-500">
                  <AlertCircle size={12} />
                  <span>{getFieldError('serverPublicKey')}</span>
                </div>
              )}
            </div>

            {/* Server KEM Public Key (optional, for identity hiding) */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                {t.editor.serverKemPublicKey || 'Server KEM Public Key'}{' '}
                <span className="text-zinc-400 dark:text-zinc-600">({t.editor.optional || 'optional'})</span>
              </label>
              <Input
                type="text"
                placeholder={t.editor.serverKemPublicKeyPlaceholder || 'Base64-encoded KEM key for identity hiding'}
                value={serverKemPublicKey}
                onChange={e => setServerKemPublicKey(e.target.value)}
                className="font-mono text-xs"
              />
              <p className="text-[10px] text-zinc-400 dark:text-zinc-600">
                {t.editor.serverKemPublicKeyDesc || 'Required for identity hiding. Encrypts the handshake initiation.'}
              </p>
            </div>

            {/* Authentication Section */}
            <div className="pt-4 border-t border-zinc-100 dark:border-white/5 space-y-4">
              <div className="flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
                <Lock size={16} />
                <span className="text-sm font-medium">{t.editor.authentication || 'Authentication'}</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-zinc-50 dark:bg-white/5">
                <div className="flex flex-col">
                  <span className="text-xs font-medium text-zinc-900 dark:text-zinc-200">
                    {t.editor.requiresAuth || 'Requires Authentication'}
                  </span>
                  <span className="text-[10px] text-zinc-500">
                    {t.editor.requiresAuthDesc || 'Server requires username and password to connect'}
                  </span>
                </div>
                <Switch checked={requiresAuth} onCheckedChange={setRequiresAuth} />
              </div>

              {requiresAuth && (
                <div className="space-y-3 animate-in fade-in slide-in-from-top-2 duration-300">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                      {t.editor.savedUsername || 'Saved Username'}{' '}
                      <span className="text-zinc-400 dark:text-zinc-600">({t.editor.optional || 'optional'})</span>
                    </label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                      <Input
                        type="text"
                        placeholder={t.editor.savedUsernamePlaceholder || 'Username to pre-fill at login'}
                        value={username}
                        onChange={e => setProfileUsername(e.target.value)}
                        className="pl-10"
                      />
                    </div>
                  </div>

                  <p className="text-[10px] text-zinc-400 dark:text-zinc-600">
                    {t.editor.savedUsernameDesc || 'Username is stored locally. Password is requested at connect time.'}
                  </p>
                </div>
              )}
            </div>

            {/* Security Level Section */}
            <div className="pt-4 border-t border-zinc-100 dark:border-white/5 space-y-4">
              <div className="flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
                <Shield size={16} />
                <span className="text-sm font-medium">{t.editor.securityLevel}</span>
              </div>

              <SegmentedControl
                value={securityLevel}
                onChange={(v) => setSecurityLevel(v as SecurityLevel)}
                options={[
                  { 
                    value: 'standard', 
                    label: <div className="flex items-center gap-2"><Shield size={12}/> {t.editor.level3}</div> 
                  },
                  { 
                    value: 'high', 
                    label: <div className="flex items-center gap-2"><ShieldCheck size={12}/> {t.editor.level5}</div> 
                  },
                ]}
              />

              <div className="text-xs text-zinc-500 dark:text-zinc-400 px-1">
                {securityLevel === 'standard' ? t.editor.level3Desc : t.editor.level5Desc}
              </div>
            </div>

            {/* Split Tunneling Section */}
            <div className="pt-4 border-t border-zinc-100 dark:border-white/5 space-y-4">
              <div className="flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
                <Split size={16} />
                <span className="text-sm font-medium">{t.editor.splitTunneling}</span>
              </div>

              <SegmentedControl
                value={tunnelMode}
                onChange={(v) => setTunnelMode(v as 'full' | 'bypass')}
                options={[
                  { value: 'full', label: <div className="flex items-center gap-2"><Globe size={12}/> {t.editor.allTraffic}</div> },
                  { value: 'bypass', label: <div className="flex items-center gap-2"><Split size={12}/> {t.editor.excludeRoutes}</div> },
                ]}
              />

              {tunnelMode === 'bypass' && (
                <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{t.editor.excludedRoutes}</label>
                    <Input
                      placeholder={t.editor.excludedRoutesPlaceholder}
                      value={routes}
                      onChange={e => setRoutes(e.target.value)}
                      onBlur={() => markTouched('routes')}
                      className={getFieldError('routes') ? 'border-red-500 dark:border-red-500' : ''}
                    />
                    {getFieldError('routes') && (
                      <div className="flex items-center gap-1 text-xs text-red-500">
                        <AlertCircle size={12} />
                        <span>{getFieldError('routes')}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg bg-zinc-50 dark:bg-white/5">
                    <div className="flex flex-col">
                      <span className="text-xs font-medium text-zinc-900 dark:text-zinc-200">{t.editor.localNetworkBypass}</span>
                      <span className="text-[10px] text-zinc-500">{t.editor.localNetworkBypassDesc}</span>
                    </div>
                    <Switch checked={bypassLocal} onCheckedChange={setBypassLocal} />
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg bg-zinc-50 dark:bg-white/5">
                    <div className="flex flex-col">
                      <span className="text-xs font-medium text-zinc-900 dark:text-zinc-200">{t.editor.lanDiscovery}</span>
                      <span className="text-[10px] text-zinc-500">{t.editor.lanDiscoveryDesc}</span>
                    </div>
                    <Switch checked={bypassDiscovery} onCheckedChange={setBypassDiscovery} />
                  </div>
                </div>
              )}
            </div>

          </form>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-zinc-100 dark:border-white/5 bg-zinc-50/50 dark:bg-black/20">
          <Button variant="ghost" onClick={onCancel}>{t.editor.cancel}</Button>
          <Button type="submit" form="profile-form" variant="primary">
            {mode === 'create' ? t.editor.create : t.editor.save}
          </Button>
        </div>

      </GlassCard>
    </div>
  );
};
