/// <reference types="vite/client" />

declare module "react" {
  export interface CSSProperties {
    [key: string]: any;
  }

  export interface HTMLAttributes<T = any> {
    className?: string;
    style?: CSSProperties;
    onClick?: (e: any) => void;
    onChange?: (e: any) => void;
    onSubmit?: (e: any) => void;
    children?: any;
    id?: string;
    key?: any;
    [key: string]: any;
  }

  export interface InputHTMLAttributes<T = any> extends HTMLAttributes<T> {
    type?: string;
    value?: any;
    placeholder?: string;
    required?: boolean;
    disabled?: boolean;
    minLength?: number;
    maxLength?: number;
    min?: any;
    max?: any;
    checked?: boolean;
    name?: string;
  }

  export interface ButtonHTMLAttributes<T = any> extends HTMLAttributes<T> {
    type?: "submit" | "reset" | "button";
    disabled?: boolean;
  }

  export type FormEvent<T = Element> = {
    preventDefault: () => void;
    stopPropagation: () => void;
    target: T;
    currentTarget: T;
    [key: string]: any;
  };

  export type ChangeEvent<T = Element> = {
    target: T & { value: string; checked?: boolean };
    currentTarget: T & { value: string; checked?: boolean };
    [key: string]: any;
  };

  export type ReactNode = any;
  export type ReactElement = any;

  export function useState<T>(initialState: T | (() => T)): [T, (newState: T | ((prevState: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: readonly any[]): void;
  export function useCallback<T extends (...args: any[]) => any>(callback: T, deps: readonly any[]): T;
  export function useMemo<T>(factory: () => T, deps: readonly any[] | undefined): T;
  export function useRef<T>(initialValue?: T): { current: T };

  export const StrictMode: any;
  const React: {
    StrictMode: any;
    useState: typeof useState;
    useEffect: typeof useEffect;
    FormEvent: any;
    [key: string]: any;
  };
  export default React;

  export namespace JSX {
    interface Element extends any {}
    interface ElementClass extends any {}
    interface IntrinsicElements {
      [elem: string]: any;
    }
  }
}

declare module "react/jsx-runtime" {
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
  export namespace JSX {
    interface Element extends any {}
    interface ElementClass extends any {}
    interface IntrinsicElements {
      [elem: string]: any;
    }
  }
}

declare module "react-dom" {
  export function createRoot(container: Element | DocumentFragment): {
    render(children: any): void;
    unmount(): void;
  };
}

declare module "react-dom/client" {
  export function createRoot(container: Element | DocumentFragment): {
    render(children: any): void;
    unmount(): void;
  };
}

declare module "lucide-react" {
  export interface IconProps {
    size?: number | string;
    color?: string;
    className?: string;
    style?: any;
    [key: string]: any;
  }
  export type Icon = (props: IconProps) => any;
  export const Activity: Icon;
  export const AlertTriangle: Icon;
  export const Award: Icon;
  export const Bug: Icon;
  export const CheckCircle: Icon;
  export const Clock: Icon;
  export const Download: Icon;
  export const FileCheck: Icon;
  export const FileText: Icon;
  export const Laptop: Icon;
  export const Plus: Icon;
  export const Radar: Icon;
  export const RefreshCw: Icon;
  export const Search: Icon;
  export const ShieldAlert: Icon;
  export const ShieldCheck: Icon;
  export const XCircle: Icon;
  const icons: { [key: string]: Icon };
  export default icons;
}

declare global {
  namespace JSX {
    interface Element extends any {}
    interface ElementClass extends any {}
    interface IntrinsicElements {
      [elem: string]: any;
    }
  }
}
