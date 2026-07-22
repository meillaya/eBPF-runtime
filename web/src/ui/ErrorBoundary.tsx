// SPDX-License-Identifier: Apache-2.0 OR MIT
import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "./Button";

interface Props {
  children: ReactNode;
  /** Panel title shown in the fallback. */
  scope?: string;
}

interface State {
  error: Error | null;
}

/**
 * Catches render-time crashes and shows a recoverable fallback instead
 * of a blank screen. Detail block is mono text, never a raw stack dump
 * spilling into the layout.
 */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`[error-boundary] ${this.props.scope ?? "view"}:`, error, info.componentStack);
  }

  private reset = (): void => {
    this.setState({ error: null });
  };

  override render(): ReactNode {
    const { error } = this.state;
    if (error === null) return this.props.children;
    return (
      <div className="well well--error" role="alert">
        <p className="well-title">Render failure — {this.props.scope ?? "this view"}</p>
        <p className="well-hint">
          The panel crashed while rendering. Telemetry collection is unaffected.
        </p>
        <p className="well-detail">{error.message}</p>
        <Button variant="secondary" onClick={this.reset}>
          Retry render
        </Button>
      </div>
    );
  }
}
