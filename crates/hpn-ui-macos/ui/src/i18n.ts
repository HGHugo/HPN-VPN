// HPN VPN Client Internationalization (EN/FR)

export type Language = 'EN' | 'FR';

export interface Translations {
  // Navigation
  nav: {
    connection: string;
    profiles: string;
    logs: string;
    settings: string;
  };
  // Connection Page
  connection: {
    title: string;
    secure: string;
    selectProfile: string;
    status: {
      disconnected: string;
      connecting: string;
      connected: string;
      disconnecting: string;
      reconnecting: string;
      error: string;
    };
    readyToConnect: string;
    establishingTunnel: string;
    closingTunnel: string;
    duration: string;
    connect: string;
    disconnect: string;
    tx: string;
    rx: string;
    latency: string;
    sessionKey: string;
    transferRate: string;
    cryptoInfo: string;
  };
  // Profiles Page
  profiles: {
    title: string;
    new: string;
    noProfiles: string;
    split: string;
    deleteConfirm: string;
    deleteTitle: string;
    deleteButton: string;
  };
  // Profile Editor
  editor: {
    newProfile: string;
    editProfile: string;
    profileName: string;
    profileNamePlaceholder: string;
    serverAddress: string;
    serverPlaceholder: string;
    port: string;
    serverPublicKey: string;
    serverPublicKeyPlaceholder: string;
    serverKemPublicKey: string;
    serverKemPublicKeyPlaceholder: string;
    serverKemPublicKeyDesc: string;
    optional: string;
    securityLevel: string;
    level3: string;
    level3Desc: string;
    level5: string;
    level5Desc: string;
    splitTunneling: string;
    allTraffic: string;
    excludeRoutes: string;
    excludedRoutes: string;
    excludedRoutesPlaceholder: string;
    localNetworkBypass: string;
    localNetworkBypassDesc: string;
    lanDiscovery: string;
    lanDiscoveryDesc: string;
    cancel: string;
    create: string;
    save: string;
    authentication: string;
    requiresAuth: string;
    requiresAuthDesc: string;
    savedUsername: string;
    savedUsernamePlaceholder: string;
    savedUsernameDesc: string;
    savedPassword: string;
    savedPasswordPlaceholder: string;
    savedCredentialsDesc: string;
  };
  // Logs Page
  logs: {
    title: string;
    clear: string;
    export: string;
    noLogs: string;
  };
  // Settings Page
  settings: {
    title: string;
    appearanceConnection: string;
    darkTheme: string;
    darkThemeDesc: string;
    autoReconnect: string;
    autoReconnectDesc: string;
    killSwitch: string;
    killSwitchDesc: string;
    cryptography: string;
    autoRekey: string;
    autoRekeyDesc: string;
    forceRekey: string;
    forceRekeyDisabled: string;
    appInfo: string;
    appVersion: string;
    cryptoDetails: string;
    // Privacy section
    privacy: string;
    webrtcLeak: string;
    webrtcLeakDesc: string;
    webrtcChromeHowto: string;
    webrtcFirefoxHowto: string;
    dnsLeak: string;
    dnsLeakDesc: string;
  };
  // Common
  common: {
    version: string;
  };
  // Validation
  validation?: {
    nameRequired: string;
    nameTooLong: string;
    invalidServer: string;
    invalidPort: string;
    invalidPublicKey: string;
    invalidKemPublicKey: string;
    invalidRoutes: string;
  };
  // Authentication
  auth?: {
    title: string;
    username: string;
    usernamePlaceholder: string;
    usernameRequired: string;
    password: string;
    passwordPlaceholder: string;
    passwordRequired: string;
    passwordNotStored: string;
    authenticating: string;
    connect: string;
  };
  // Auto-updater (audit H14) — strings consumed by
  // `components/UpdateAvailableModal.tsx`. Optional for backwards
  // compatibility with older binaries shipping older translations.
  updater?: {
    title: string;
    releaseNotes: string;
    readyToInstall: string;
    downloadAndInstall: string;
    later: string;
    downloading: string;
    installing: string;
    installFailed: string;
    retry: string;
  };
}

const translations: Record<Language, Translations> = {
  EN: {
    nav: {
      connection: 'Connection',
      profiles: 'Profiles',
      logs: 'Logs',
      settings: 'Settings',
    },
    connection: {
      title: 'Connection',
      secure: 'Secure',
      selectProfile: 'Select a profile',
      status: {
        disconnected: 'Disconnected',
        connecting: 'Connecting',
        connected: 'Connected',
        disconnecting: 'Disconnecting',
        reconnecting: 'Reconnecting',
        error: 'Error',
      },
      readyToConnect: 'Ready to connect',
      establishingTunnel: 'Establishing secure tunnel...',
      closingTunnel: 'Closing tunnel...',
      duration: 'Duration',
      connect: 'Connect',
      disconnect: 'Disconnect',
      tx: 'TX',
      rx: 'RX',
      latency: 'Latency',
      sessionKey: 'Session Key',
      transferRate: 'Transfer Rate',
      cryptoInfo: 'X25519 + ML-KEM-1024 | ML-DSA-87 | AES-256-GCM',
    },
    profiles: {
      title: 'Profiles',
      new: 'New',
      noProfiles: 'No profiles configured',
      split: 'Split',
      deleteConfirm: 'This profile will be permanently deleted. This action cannot be undone.',
      deleteTitle: 'Delete Profile',
      deleteButton: 'Delete',
    },
    editor: {
      newProfile: 'New Profile',
      editProfile: 'Edit Profile',
      profileName: 'Profile Name',
      profileNamePlaceholder: 'e.g. Work VPN',
      serverAddress: 'Server Address',
      serverPlaceholder: 'vpn.example.com',
      port: 'Port',
      serverPublicKey: 'Server Public Key',
      serverPublicKeyPlaceholder: 'Base64-encoded server public key...',
      serverKemPublicKey: 'Server KEM Public Key',
      serverKemPublicKeyPlaceholder: 'Base64-encoded KEM key for identity hiding',
      serverKemPublicKeyDesc: 'Required for identity hiding. Encrypts the handshake initiation.',
      optional: 'optional',
      securityLevel: 'Security Level',
      level3: 'Level 3 (Recommended)',
      level3Desc: 'ML-KEM-768 + ML-DSA-65 (~AES-192)',
      level5: 'Level 5 (Maximum)',
      level5Desc: 'ML-KEM-1024 + ML-DSA-87 (~AES-256)',
      splitTunneling: 'Split Tunneling',
      allTraffic: 'All Traffic',
      excludeRoutes: 'Exclude Routes',
      excludedRoutes: 'Excluded Routes (CIDR)',
      excludedRoutesPlaceholder: '192.168.1.0/24, 10.0.0.0/8',
      localNetworkBypass: 'Local Network Bypass',
      localNetworkBypassDesc: '10.x, 172.16-31.x, 192.168.x',
      lanDiscovery: 'LAN Discovery',
      lanDiscoveryDesc: 'Allow mDNS, Bonjour, SSDP',
      cancel: 'Cancel',
      create: 'Create Profile',
      save: 'Save Changes',
      authentication: 'Authentication',
      requiresAuth: 'Requires Authentication',
      requiresAuthDesc: 'Server requires username/password to connect',
      savedUsername: 'Saved Username',
      savedUsernamePlaceholder: 'Enter username to save',
      savedUsernameDesc: 'Password will be requested at connection time',
      savedPassword: 'Saved Password',
      savedPasswordPlaceholder: 'Enter password to save',
      savedCredentialsDesc: 'Credentials are stored locally on this device.',
    },
    logs: {
      title: 'Logs',
      clear: 'Clear',
      export: 'Export',
      noLogs: 'No active logs',
    },
    settings: {
      title: 'Settings',
      appearanceConnection: 'Appearance & Connection',
      darkTheme: 'Dark Theme',
      darkThemeDesc: 'Use dark mode interface',
      autoReconnect: 'Auto Reconnect',
      autoReconnectDesc: 'Reconnect if VPN tunnel is lost',
      killSwitch: 'Kill Switch',
      killSwitchDesc: 'Always on. Cannot be disabled.',
      cryptography: 'Cryptography',
      autoRekey: 'Automatic Re-key',
      autoRekeyDesc: 'Rotate session keys every 60 min',
      forceRekey: 'Force Re-key',
      forceRekeyDisabled: 'Connect to VPN to use this action.',
      appInfo: 'App Info',
      appVersion: 'HPN v0.1.1 — Post-quantum VPN client',
      cryptoDetails: 'Using MLKEM1024, MLDSA87, AES-256-GCM\n(Optional Hybrid X25519+MLKEM)',
      privacy: 'Privacy & Leak Protection',
      webrtcLeak: 'WebRTC IP Leak',
      webrtcLeakDesc:
        'Modern browsers use WebRTC for video/voice calls. WebRTC can reveal your real IP address through STUN, even when this VPN is active. The VPN cannot block this from outside the browser — you must disable or restrict WebRTC in your browser settings.',
      webrtcChromeHowto:
        'Chrome / Edge: install the "WebRTC Network Limiter" extension and set the policy to "default public interface only".',
      webrtcFirefoxHowto:
        'Firefox: open about:config and set media.peerconnection.enabled to false (disables WebRTC entirely). Safari: WebRTC is harder to disable; consider an extension that blocks STUN.',
      dnsLeak: 'DNS Leak Protection',
      dnsLeakDesc:
        'DNS queries are pinned to the VPN tunnel. We additionally block browser-level DNS-over-HTTPS / DNS-over-TLS resolvers and multicast DNS so that no application can bypass the tunnel\'s DNS settings.',
    },
    common: {
      version: 'v0.1.1',
    },
    validation: {
      nameRequired: 'Profile name is required',
      nameTooLong: 'Profile name must be 100 characters or less',
      invalidServer: 'Invalid server address (hostname or IP)',
      invalidPort: 'Port must be between 1 and 65535',
      invalidPublicKey: 'Invalid public key format (base64)',
      invalidKemPublicKey: 'Invalid KEM public key format (base64)',
      invalidRoutes: 'Invalid CIDR routes',
    },
    auth: {
      title: 'Authentication Required',
      username: 'Username',
      usernamePlaceholder: 'Enter your username',
      usernameRequired: 'Username is required',
      password: 'Password',
      passwordPlaceholder: 'Enter your password',
      passwordRequired: 'Password is required',
      passwordNotStored: 'Your password is never stored locally and is encrypted before transmission.',
      authenticating: 'Authenticating...',
      connect: 'Connect',
    },
    updater: {
      title: 'Update available',
      releaseNotes: 'Release notes',
      readyToInstall: 'A new version is ready to install.',
      downloadAndInstall: 'Download & install',
      later: 'Later',
      downloading: 'Downloading…',
      installing: 'Installing…',
      installFailed: 'Update failed',
      retry: 'Retry',
    },
  },
  FR: {
    nav: {
      connection: 'Connexion',
      profiles: 'Profils',
      logs: 'Journaux',
      settings: 'Paramètres',
    },
    connection: {
      title: 'Connexion',
      secure: 'Sécurisé',
      selectProfile: 'Sélectionner un profil',
      status: {
        disconnected: 'Déconnecté',
        connecting: 'Connexion...',
        connected: 'Connecté',
        disconnecting: 'Déconnexion...',
        reconnecting: 'Reconnexion...',
        error: 'Erreur',
      },
      readyToConnect: 'Prêt à se connecter',
      establishingTunnel: 'Établissement du tunnel sécurisé...',
      closingTunnel: 'Fermeture du tunnel...',
      duration: 'Durée',
      connect: 'Connecter',
      disconnect: 'Déconnecter',
      tx: 'TX',
      rx: 'RX',
      latency: 'Latence',
      sessionKey: 'Clé de session',
      transferRate: 'Débit',
      cryptoInfo: 'X25519 + ML-KEM-1024 | ML-DSA-87 | AES-256-GCM',
    },
    profiles: {
      title: 'Profils',
      new: 'Nouveau',
      noProfiles: 'Aucun profil configuré',
      split: 'Split',
      deleteConfirm: 'Ce profil sera définitivement supprimé. Cette action est irréversible.',
      deleteTitle: 'Supprimer le profil',
      deleteButton: 'Supprimer',
    },
    editor: {
      newProfile: 'Nouveau profil',
      editProfile: 'Modifier le profil',
      profileName: 'Nom du profil',
      profileNamePlaceholder: 'ex. VPN Travail',
      serverAddress: 'Adresse du serveur',
      serverPlaceholder: 'vpn.exemple.com',
      port: 'Port',
      serverPublicKey: 'Clé publique du serveur',
      serverPublicKeyPlaceholder: 'Clé publique encodée en Base64...',
      serverKemPublicKey: 'Clé publique KEM du serveur',
      serverKemPublicKeyPlaceholder: 'Clé KEM encodée en Base64 pour masquage d\'identité',
      serverKemPublicKeyDesc: 'Requis pour le masquage d\'identité. Chiffre l\'initiation du handshake.',
      optional: 'optionnel',
      securityLevel: 'Niveau de sécurité',
      level3: 'Niveau 3 (Recommandé)',
      level3Desc: 'ML-KEM-768 + ML-DSA-65 (~AES-192)',
      level5: 'Niveau 5 (Maximum)',
      level5Desc: 'ML-KEM-1024 + ML-DSA-87 (~AES-256)',
      splitTunneling: 'Tunneling divisé',
      allTraffic: 'Tout le trafic',
      excludeRoutes: 'Exclure des routes',
      excludedRoutes: 'Routes exclues (CIDR)',
      excludedRoutesPlaceholder: '192.168.1.0/24, 10.0.0.0/8',
      localNetworkBypass: 'Contourner le réseau local',
      localNetworkBypassDesc: '10.x, 172.16-31.x, 192.168.x',
      lanDiscovery: 'Découverte LAN',
      lanDiscoveryDesc: 'Autoriser mDNS, Bonjour, SSDP',
      cancel: 'Annuler',
      create: 'Créer le profil',
      save: 'Enregistrer',
      authentication: 'Authentification',
      requiresAuth: 'Authentification requise',
      requiresAuthDesc: 'Le serveur nécessite un nom d\'utilisateur/mot de passe',
      savedUsername: 'Nom d\'utilisateur enregistré',
      savedUsernamePlaceholder: 'Entrez le nom d\'utilisateur à enregistrer',
      savedUsernameDesc: 'Le mot de passe sera demandé lors de la connexion',
      savedPassword: 'Mot de passe enregistré',
      savedPasswordPlaceholder: 'Entrez le mot de passe à enregistrer',
      savedCredentialsDesc: 'Les identifiants sont stockés localement sur cet appareil.',
    },
    logs: {
      title: 'Journaux',
      clear: 'Effacer',
      export: 'Exporter',
      noLogs: 'Aucun journal actif',
    },
    settings: {
      title: 'Paramètres',
      appearanceConnection: 'Apparence & Connexion',
      darkTheme: 'Thème sombre',
      darkThemeDesc: 'Utiliser le mode sombre',
      autoReconnect: 'Reconnexion auto',
      autoReconnectDesc: 'Reconnecter si le tunnel VPN est perdu',
      killSwitch: 'Kill Switch',
      killSwitchDesc: 'Toujours actif. Ne peut pas être désactivé.',
      cryptography: 'Cryptographie',
      autoRekey: 'Re-clé automatique',
      autoRekeyDesc: 'Rotation des clés toutes les 60 min',
      forceRekey: 'Forcer Re-clé',
      forceRekeyDisabled: 'Connectez-vous au VPN pour utiliser cette action.',
      privacy: 'Confidentialité & Protection des fuites',
      webrtcLeak: 'Fuite d\'IP WebRTC',
      webrtcLeakDesc:
        'Les navigateurs modernes utilisent WebRTC pour les appels audio/vidéo. WebRTC peut révéler votre adresse IP réelle via STUN, même lorsque ce VPN est actif. Le VPN ne peut pas bloquer cela depuis l\'extérieur du navigateur — vous devez désactiver ou restreindre WebRTC dans les paramètres de votre navigateur.',
      webrtcChromeHowto:
        'Chrome / Edge : installez l\'extension « WebRTC Network Limiter » et choisissez le mode « default public interface only ».',
      webrtcFirefoxHowto:
        'Firefox : ouvrez about:config et passez media.peerconnection.enabled à false (désactive WebRTC). Safari : WebRTC est plus difficile à désactiver ; envisagez une extension qui bloque STUN.',
      dnsLeak: 'Protection des fuites DNS',
      dnsLeakDesc:
        'Les requêtes DNS sont forcées dans le tunnel VPN. Nous bloquons en plus les résolveurs DNS-over-HTTPS / DNS-over-TLS au niveau navigateur ainsi que le DNS multicast, pour qu\'aucune application ne puisse contourner les paramètres DNS du tunnel.',
      appInfo: 'Info App',
      appVersion: 'HPN v0.1.1 — Client VPN post-quantique',
      cryptoDetails: 'Utilise MLKEM1024, MLDSA87, AES-256-GCM\n(Hybride optionnel X25519+MLKEM)',
    },
    common: {
      version: 'v0.1.1',
    },
    validation: {
      nameRequired: 'Le nom du profil est requis',
      nameTooLong: 'Le nom du profil doit comporter 100 caractères ou moins',
      invalidServer: 'Adresse serveur invalide (nom d\'hôte ou IP)',
      invalidPort: 'Le port doit être entre 1 et 65535',
      invalidPublicKey: 'Format de clé publique invalide (base64)',
      invalidKemPublicKey: 'Format de clé publique KEM invalide (base64)',
      invalidRoutes: 'Routes CIDR invalides',
    },
    auth: {
      title: 'Authentification requise',
      username: 'Nom d\'utilisateur',
      usernamePlaceholder: 'Entrez votre nom d\'utilisateur',
      usernameRequired: 'Nom d\'utilisateur requis',
      password: 'Mot de passe',
      passwordPlaceholder: 'Entrez votre mot de passe',
      passwordRequired: 'Mot de passe requis',
      passwordNotStored: 'Votre mot de passe n\'est jamais stocké localement et est chiffré avant transmission.',
      authenticating: 'Authentification...',
      connect: 'Connecter',
    },
    updater: {
      title: 'Mise à jour disponible',
      releaseNotes: 'Notes de version',
      readyToInstall: 'Une nouvelle version est prête à être installée.',
      downloadAndInstall: 'Télécharger et installer',
      later: 'Plus tard',
      downloading: 'Téléchargement…',
      installing: 'Installation…',
      installFailed: 'Échec de la mise à jour',
      retry: 'Réessayer',
    },
  },
};

export const getTranslations = (lang: Language): Translations => translations[lang];

export const useTranslations = (lang: Language) => {
  return translations[lang];
};
