import React from 'react';
import { Loader2, X, AlertCircle, CheckCircle, AlertTriangle, Info, Wifi, WifiOff } from 'lucide-react';

// Utility for class merging
export const cn = (...classes: (string | undefined | null | false)[]) => {
  return classes.filter(Boolean).join(' ');
};

// --- Surface Components ---

export interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: React.ReactNode;
  className?: string;
  onClick?: React.MouseEventHandler<HTMLDivElement>;
}

export const GlassCard: React.FC<GlassCardProps> = ({ children, className, ...props }) => (
  <div 
    className={cn(
      // Light: White bg, subtle border, shadow
      // Dark: Surface/60 bg, blur, light border
      "bg-white/80 dark:bg-surface/60 backdrop-blur-xl border border-zinc-200 dark:border-border rounded-2xl shadow-sm",
      "transition-all duration-200",
      className
    )}
    {...props}
  >
    {children}
  </div>
);

export interface BadgeProps {
  children?: React.ReactNode;
  variant?: 'default' | 'outline' | 'red';
  className?: string;
}

export const Badge = ({ children, variant = 'default', className }: BadgeProps) => {
  const variants = {
    default: "bg-zinc-100 dark:bg-white/10 text-zinc-700 dark:text-zinc-200 border-transparent",
    outline: "bg-transparent border-zinc-300 dark:border-white/10 text-zinc-500 dark:text-zinc-400 border",
    red: "bg-red-50 dark:bg-accent/10 text-red-600 dark:text-red-400 border-red-200 dark:border-accent/20 border"
  };
  
  return (
    <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-medium tracking-wide border", variants[variant], className)}>
      {children}
    </span>
  );
};

// --- Form Elements ---

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'outline' | 'danger';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  isLoading?: boolean;
  className?: string;
  disabled?: boolean;
  children?: React.ReactNode;
  onClick?: React.MouseEventHandler<HTMLButtonElement>;
  type?: "button" | "submit" | "reset";
  form?: string;
}

export const Button: React.FC<ButtonProps> = ({ 
  children, 
  variant = 'primary', 
  size = 'md', 
  isLoading, 
  className, 
  disabled,
  ...props
}) => {
  
  const baseStyles = "inline-flex items-center justify-center font-medium transition-colors focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50 disabled:pointer-events-none rounded-lg";
  
  const variants = {
    primary: "bg-accent hover:bg-accent-hover text-white shadow-lg shadow-accent/20",
    ghost: "bg-transparent hover:bg-zinc-100 dark:hover:bg-white/5 text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100",
    outline: "bg-transparent border border-zinc-200 dark:border-white/10 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-white/5 hover:border-zinc-300 dark:hover:border-white/20",
    danger: "bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40"
  };

  const sizes = {
    sm: "h-8 px-3 text-xs",
    md: "h-10 px-4 text-sm",
    lg: "h-12 px-6 text-base",
    icon: "h-9 w-9 p-0"
  };

  return (
    <button 
      className={cn(baseStyles, variants[variant], sizes[size], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
      {children}
    </button>
  );
};

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...props }, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-9 w-full rounded-lg border px-3 py-1 text-sm shadow-sm transition-colors",
        // Light: white bg, zinc border, dark text
        // Dark: black/20 bg, white/10 border, light text
        "bg-white dark:bg-black/20 border-zinc-200 dark:border-white/10",
        "text-zinc-900 dark:text-zinc-200",
        "placeholder:text-zinc-400 dark:placeholder:text-zinc-600",
        "file:border-0 file:bg-transparent file:text-sm file:font-medium",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent/50 focus-visible:border-accent/50",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    />
  );
});

export const Switch = ({ checked, onCheckedChange, disabled }: { checked: boolean; onCheckedChange?: (c: boolean) => void; disabled?: boolean }) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    disabled={disabled}
    onClick={() => !disabled && onCheckedChange?.(!checked)}
    className={cn(
      "relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
      checked ? "bg-accent" : "bg-zinc-200 dark:bg-zinc-800",
      disabled && "opacity-50 cursor-not-allowed"
    )}
  >
    <span
      className={cn(
        "pointer-events-none block h-4 w-4 rounded-full bg-white shadow-lg ring-0 transition-transform",
        checked ? "translate-x-4" : "translate-x-0"
      )}
    />
  </button>
);

export const SegmentedControl = ({ options, value, onChange }: { options: { value: string, label: React.ReactNode }[], value: string, onChange: (val: string) => void }) => (
  <div className="flex p-1 bg-zinc-100 dark:bg-black/40 rounded-lg border border-zinc-200 dark:border-white/5">
    {options.map((opt) => {
      const isActive = value === opt.value;
      return (
        <button
          type="button"
          key={opt.value}
          onClick={() => onChange(opt.value)}
          className={cn(
            "flex-1 flex items-center justify-center py-1.5 text-xs font-medium rounded-md transition-all",
            isActive
              ? "bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white shadow-sm"
              : "text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
          )}
        >
          {opt.label}
        </button>
      );
    })}
  </div>
);

// --- Toast / Notification System ---

export type ToastType = 'error' | 'success' | 'warning' | 'info';

export interface ToastData {
  id: string;
  message: string;
  type: ToastType;
  title?: string;
  duration?: number;
}

export interface ToastProps {
  toast: ToastData;
  onClose: (id: string) => void;
}

// Progress bar for auto-close countdown
const ToastProgress: React.FC<{ duration: number }> = ({ duration }) => {
  const [progress, setProgress] = React.useState(100);

  React.useEffect(() => {
    const interval = 50; // Update every 50ms for smooth animation
    const decrement = (interval / duration) * 100;

    const timer = setInterval(() => {
      setProgress(prev => Math.max(0, prev - decrement));
    }, interval);

    return () => clearInterval(timer);
  }, [duration]);

  return (
    <div className="absolute bottom-0 left-0 right-0 h-1 bg-black/10 dark:bg-white/10 rounded-b-xl overflow-hidden">
      <div
        className="h-full bg-current opacity-30 transition-all duration-50 ease-linear"
        style={{ width: `${progress}%` }}
      />
    </div>
  );
};

export const Toast: React.FC<ToastProps> = ({ toast, onClose }) => {
  const { id, message, type, title, duration = 8000 } = toast;

  React.useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => onClose(id), duration);
      return () => clearTimeout(timer);
    }
  }, [duration, id, onClose]);

  const config = {
    error: {
      icon: <AlertCircle className="w-5 h-5" />,
      bg: "bg-red-50 dark:bg-red-950/60 border-red-200/50 dark:border-red-800/50",
      text: "text-red-700 dark:text-red-300",
      iconColor: "text-red-500 dark:text-red-400"
    },
    success: {
      icon: <CheckCircle className="w-5 h-5" />,
      bg: "bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200/50 dark:border-emerald-800/50",
      text: "text-emerald-700 dark:text-emerald-300",
      iconColor: "text-emerald-500 dark:text-emerald-400"
    },
    warning: {
      icon: <AlertTriangle className="w-5 h-5" />,
      bg: "bg-amber-50 dark:bg-amber-950/60 border-amber-200/50 dark:border-amber-800/50",
      text: "text-amber-700 dark:text-amber-300",
      iconColor: "text-amber-500 dark:text-amber-400"
    },
    info: {
      icon: <Info className="w-5 h-5" />,
      bg: "bg-blue-50 dark:bg-blue-950/60 border-blue-200/50 dark:border-blue-800/50",
      text: "text-blue-700 dark:text-blue-300",
      iconColor: "text-blue-500 dark:text-blue-400"
    }
  };

  const c = config[type];

  return (
    <div className={cn(
      "relative flex items-start gap-3 p-4 rounded-xl border shadow-xl backdrop-blur-md",
      "animate-in slide-in-from-bottom-2 fade-in duration-200",
      c.bg, c.text
    )}>
      <div className={cn("flex-shrink-0 mt-0.5", c.iconColor)}>
        {c.icon}
      </div>
      <div className="flex-1 min-w-0">
        {title && (
          <p className="font-semibold text-sm mb-0.5">{title}</p>
        )}
        <p className="text-sm opacity-90 break-words">{message}</p>
      </div>
      <button
        onClick={() => onClose(id)}
        className={cn(
          "flex-shrink-0 p-1.5 rounded-lg transition-all",
          "hover:bg-black/5 dark:hover:bg-white/10",
          "opacity-60 hover:opacity-100"
        )}
      >
        <X className="w-4 h-4" />
      </button>
      {duration > 0 && <ToastProgress duration={duration} />}
    </div>
  );
};

// Toast Container for multiple toasts
export interface ToastContainerProps {
  toasts: ToastData[];
  onClose: (id: string) => void;
  position?: 'top' | 'bottom';
}

export const ToastContainer: React.FC<ToastContainerProps> = ({
  toasts,
  onClose,
  position = 'bottom'
}) => {
  if (toasts.length === 0) return null;

  return (
    <div className={cn(
      "fixed left-1/2 -translate-x-1/2 z-50 flex flex-col gap-2 w-[90%] max-w-md",
      position === 'bottom' ? "bottom-24" : "top-6"
    )}>
      {toasts.map((toast) => (
        <Toast key={toast.id} toast={toast} onClose={onClose} />
      ))}
    </div>
  );
};

// Hook for managing toasts
export const useToasts = () => {
  const [toasts, setToasts] = React.useState<ToastData[]>([]);

  const addToast = React.useCallback((
    message: string,
    type: ToastType = 'info',
    options?: { title?: string; duration?: number }
  ) => {
    const id = Math.random().toString(36).substring(2, 9);
    const newToast: ToastData = {
      id,
      message,
      type,
      title: options?.title,
      duration: options?.duration ?? 8000
    };
    setToasts(prev => [...prev.slice(-4), newToast]); // Keep max 5 toasts
    return id;
  }, []);

  const removeToast = React.useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const clearToasts = React.useCallback(() => {
    setToasts([]);
  }, []);

  return { toasts, addToast, removeToast, clearToasts };
};

// --- Confirm Dialog ---

export interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'default';
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  message,
  confirmLabel = 'Delete',
  cancelLabel = 'Cancel',
  variant = 'danger',
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  return (
    <div className="absolute inset-0 z-[60] flex items-center justify-center p-4 bg-black/50 dark:bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
      <div className={cn(
        "w-full max-w-[340px] bg-white dark:bg-zinc-900 rounded-2xl shadow-2xl border border-zinc-200 dark:border-white/10",
        "animate-in zoom-in-95 duration-200"
      )}>
        <div className="px-6 pt-6 pb-2">
          <div className="flex items-center gap-3 mb-3">
            <div className={cn(
              "flex items-center justify-center w-10 h-10 rounded-full",
              variant === 'danger'
                ? "bg-red-100 dark:bg-red-950/50"
                : "bg-zinc-100 dark:bg-zinc-800"
            )}>
              <AlertTriangle className={cn(
                "w-5 h-5",
                variant === 'danger'
                  ? "text-red-600 dark:text-red-400"
                  : "text-zinc-600 dark:text-zinc-400"
              )} />
            </div>
            <h3 className="text-base font-semibold text-zinc-900 dark:text-white">{title}</h3>
          </div>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 leading-relaxed pl-[52px]">{message}</p>
        </div>
        <div className="flex items-center justify-end gap-2 px-6 py-4">
          <Button variant="ghost" size="sm" onClick={onCancel}>
            {cancelLabel}
          </Button>
          <Button
            variant={variant === 'danger' ? 'danger' : 'primary'}
            size="sm"
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
};

// Connection Status Banner (for persistent connection state display)
export interface ConnectionBannerProps {
  status: 'connecting' | 'connected' | 'disconnecting' | 'reconnecting' | 'error';
  message?: string;
  onRetry?: () => void;
}

export const ConnectionBanner: React.FC<ConnectionBannerProps> = ({
  status,
  message,
  onRetry
}) => {
  const config = {
    connecting: {
      icon: <Loader2 className="w-4 h-4 animate-spin" />,
      bg: "bg-blue-500/10 border-blue-500/20",
      text: "text-blue-600 dark:text-blue-400",
      label: "Connecting..."
    },
    connected: {
      icon: <Wifi className="w-4 h-4" />,
      bg: "bg-emerald-500/10 border-emerald-500/20",
      text: "text-emerald-600 dark:text-emerald-400",
      label: "Connected"
    },
    disconnecting: {
      icon: <Loader2 className="w-4 h-4 animate-spin" />,
      bg: "bg-zinc-500/10 border-zinc-500/20",
      text: "text-zinc-600 dark:text-zinc-400",
      label: "Disconnecting..."
    },
    reconnecting: {
      icon: <Loader2 className="w-4 h-4 animate-spin" />,
      bg: "bg-amber-500/10 border-amber-500/20",
      text: "text-amber-600 dark:text-amber-400",
      label: "Reconnecting..."
    },
    error: {
      icon: <WifiOff className="w-4 h-4" />,
      bg: "bg-red-500/10 border-red-500/20",
      text: "text-red-600 dark:text-red-400",
      label: "Connection Error"
    }
  };

  const c = config[status];

  return (
    <div className={cn(
      "flex items-center justify-between gap-3 px-4 py-2.5 rounded-xl border",
      "animate-in fade-in duration-200",
      c.bg
    )}>
      <div className={cn("flex items-center gap-2", c.text)}>
        {c.icon}
        <span className="text-sm font-medium">{message || c.label}</span>
      </div>
      {status === 'error' && onRetry && (
        <button
          onClick={onRetry}
          className={cn(
            "text-xs font-medium px-3 py-1 rounded-lg",
            "bg-red-500/20 hover:bg-red-500/30 transition-colors",
            c.text
          )}
        >
          Retry
        </button>
      )}
    </div>
  );
};