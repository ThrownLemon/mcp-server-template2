import type { CancellationToken } from '../types/index.js';

export class CancellationTokenImpl implements CancellationToken {
  private _isCancelled = false;
  private _reason?: string;
  private _callbacks: Array<(reason?: string) => void> = [];

  get isCancelled(): boolean {
    return this._isCancelled;
  }

  get reason(): string | undefined {
    return this._reason;
  }

  cancel(reason?: string): void {
    if (this._isCancelled) return;
    
    this._isCancelled = true;
    this._reason = reason;
    
    for (const callback of this._callbacks) {
      try {
        callback(reason);
      } catch (error) {
        console.error('Error in cancellation callback:', error);
      }
    }
  }

  onCancelled(callback: (reason?: string) => void): void {
    if (this._isCancelled) {
      callback(this._reason);
    } else {
      this._callbacks.push(callback);
    }
  }

  throwIfCancelled(): void {
    if (this._isCancelled) {
      throw new Error(`Operation cancelled${this._reason ? `: ${this._reason}` : ''}`);
    }
  }
}

export class CancellationTokenSource {
  private _token = new CancellationTokenImpl();

  get token(): CancellationToken {
    return this._token;
  }

  cancel(reason?: string): void {
    this._token.cancel(reason);
  }
}

export const createTimeoutToken = (timeoutMs: number, reason = 'Timeout'): CancellationToken => {
  const source = new CancellationTokenSource();
  setTimeout(() => source.cancel(reason), timeoutMs);
  return source.token;
};

export const createCombinedToken = (...tokens: CancellationToken[]): CancellationToken => {
  const source = new CancellationTokenSource();
  
  for (const token of tokens) {
    token.onCancelled((reason) => {
      source.cancel(reason);
    });
  }
  
  return source.token;
};