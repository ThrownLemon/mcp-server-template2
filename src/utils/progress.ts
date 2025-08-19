import { EventEmitter } from 'events';
import type { ProgressTracker } from '../types/index.js';
import { progressUpdateInterval } from './config.js';

export class ProgressTrackerImpl extends EventEmitter implements ProgressTracker {
  public readonly id: string;
  public readonly startTime: Date;
  public endTime?: Date;
  
  private _total: number;
  private _current: number;
  private _status: ProgressTracker['status'];
  private _message?: string;
  private _lastUpdate: number = 0;

  constructor(id: string, total: number, message?: string) {
    super();
    this.id = id;
    this._total = total;
    this._current = 0;
    this._status = 'pending';
    this._message = message;
    this.startTime = new Date();
  }

  get total(): number {
    return this._total;
  }

  get current(): number {
    return this._current;
  }

  get status(): ProgressTracker['status'] {
    return this._status;
  }

  get message(): string | undefined {
    return this._message;
  }

  get progress(): number {
    return this._total > 0 ? this._current / this._total : 0;
  }

  get percentage(): number {
    return Math.round(this.progress * 100);
  }

  start(message?: string): void {
    if (this._status !== 'pending') return;
    
    this._status = 'running';
    this._message = message ?? this._message;
    this._emitUpdate();
  }

  update(current: number, message?: string): void {
    if (this._status !== 'running') return;
    
    this._current = Math.max(0, Math.min(current, this._total));
    if (message) this._message = message;
    
    const now = Date.now();
    if (now - this._lastUpdate >= progressUpdateInterval) {
      this._emitUpdate();
      this._lastUpdate = now;
    }

    if (this._current >= this._total) {
      this.complete();
    }
  }

  increment(amount = 1, message?: string): void {
    this.update(this._current + amount, message);
  }

  complete(message?: string): void {
    if (this._status === 'completed' || this._status === 'failed') return;
    
    this._status = 'completed';
    this._current = this._total;
    this._message = message ?? this._message ?? 'Completed';
    this.endTime = new Date();
    this._emitUpdate();
  }

  fail(message?: string, error?: Error): void {
    if (this._status === 'completed' || this._status === 'failed') return;
    
    this._status = 'failed';
    this._message = message ?? error?.message ?? 'Failed';
    this.endTime = new Date();
    this._emitUpdate();
  }

  private _emitUpdate(): void {
    this.emit('progress', {
      id: this.id,
      total: this._total,
      current: this._current,
      status: this._status,
      message: this._message,
      startTime: this.startTime,
      endTime: this.endTime,
      progress: this.progress,
      percentage: this.percentage
    });
  }

  toJSON(): ProgressTracker & { progress: number; percentage: number } {
    return {
      id: this.id,
      total: this._total,
      current: this._current,
      status: this._status,
      message: this._message,
      startTime: this.startTime,
      endTime: this.endTime,
      progress: this.progress,
      percentage: this.percentage
    };
  }
}

export class ProgressManager extends EventEmitter {
  private _trackers = new Map<string, ProgressTrackerImpl>();

  create(id: string, total: number, message?: string): ProgressTrackerImpl {
    if (this._trackers.has(id)) {
      throw new Error(`Progress tracker with id '${id}' already exists`);
    }

    const tracker = new ProgressTrackerImpl(id, total, message);
    this._trackers.set(id, tracker);

    tracker.on('progress', (data) => {
      this.emit('progress', data);
      
      if (data.status === 'completed' || data.status === 'failed') {
        setTimeout(() => this._trackers.delete(id), 60000); // Clean up after 1 minute
      }
    });

    return tracker;
  }

  get(id: string): ProgressTrackerImpl | undefined {
    return this._trackers.get(id);
  }

  getAll(): ProgressTrackerImpl[] {
    return Array.from(this._trackers.values());
  }

  remove(id: string): boolean {
    return this._trackers.delete(id);
  }

  clear(): void {
    this._trackers.clear();
  }
}

export const globalProgressManager = new ProgressManager();