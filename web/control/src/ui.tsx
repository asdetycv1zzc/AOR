import {
  ButtonHTMLAttributes,
  createContext,
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  TextareaHTMLAttributes,
  useContext,
} from "react";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  appearance?: "primary" | "secondary" | "subtle" | "outline";
  size?: "small" | "medium" | "large";
  icon?: ReactNode;
  iconPosition?: "before" | "after";
};

export function Button({ appearance = "secondary", size = "medium", icon, iconPosition = "before", className = "", children, type = "button", ...props }: ButtonProps) {
  return (
    <button type={type} className={`ui-button ui-button-${appearance} ui-button-${size} ${className}`} {...props}>
      {icon && iconPosition === "before" && <span className="ui-button-icon">{icon}</span>}
      {children && <span className="ui-button-label">{children}</span>}
      {icon && iconPosition === "after" && <span className="ui-button-icon">{icon}</span>}
    </button>
  );
}

export function Tooltip({ content, children }: { content: string; relationship?: string; children: ReactNode }) {
  return <span className="ui-tooltip-wrap" title={content}>{children}</span>;
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "onChange"> & {
  onChange?: (event: React.ChangeEvent<HTMLInputElement>, data: { value: string }) => void;
};

export function Input({ onChange, className = "", ...props }: InputProps) {
  return <input className={`ui-input ${className}`} onChange={(event) => onChange?.(event, { value: event.target.value })} {...props} />;
}

type TextareaProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "onChange"> & {
  onChange?: (event: React.ChangeEvent<HTMLTextAreaElement>, data: { value: string }) => void;
  resize?: "none" | "vertical" | "horizontal" | "both";
};

export function Textarea({ onChange, resize = "none", className = "", style, ...props }: TextareaProps) {
  return (
    <textarea
      className={`ui-textarea ${className}`}
      style={{ ...style, resize }}
      onChange={(event) => onChange?.(event, { value: event.target.value })}
      {...props}
    />
  );
}

export function Field({ label, required, children }: { label: string; required?: boolean; children: ReactNode }) {
  return (
    <label className="ui-field">
      <span>{label}{required && <b aria-hidden="true"> *</b>}</span>
      {children}
    </label>
  );
}

export function Spinner({ size = "small", label }: { size?: "tiny" | "small" | "medium"; label?: string }) {
  return (
    <span className={`ui-spinner ui-spinner-${size}`} role="status">
      <span className="ui-spinner-ring" aria-hidden="true" />
      {label && <span>{label}</span>}
    </span>
  );
}

const DialogCloseContext = createContext<(() => void) | undefined>(undefined);

export function Dialog({ open, onOpenChange, children }: {
  open: boolean;
  onOpenChange?: (event: unknown, data: { open: boolean }) => void;
  children: ReactNode;
}) {
  if (!open) return null;
  const close = () => onOpenChange?.(undefined, { open: false });
  return (
    <DialogCloseContext.Provider value={close}>
      <div className="ui-dialog-backdrop" onMouseDown={(event) => event.target === event.currentTarget && close()}>
        {children}
      </div>
    </DialogCloseContext.Provider>
  );
}

export function DialogSurface({ children, className = "" }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-dialog-surface ${className}`} role="dialog" aria-modal="true">{children}</div>;
}

export function DialogBody({ children, className = "" }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-dialog-body ${className}`}>{children}</div>;
}

export function DialogTitle({ children, className = "" }: HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={`ui-dialog-title ${className}`}>{children}</h2>;
}

export function DialogContent({ children, className = "" }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-dialog-content ${className}`}>{children}</div>;
}

export function DialogActions({ children, className = "" }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-dialog-actions ${className}`}>{children}</div>;
}

export function useDialogClose(): (() => void) | undefined {
  return useContext(DialogCloseContext);
}
