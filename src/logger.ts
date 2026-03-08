type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private level: number;

  constructor(logLevel: LogLevel = 'info') {
    this.level = LEVELS[logLevel];
  }

  debug(message: string, meta?: object): void {
    if (this.level <= LEVELS.debug) {
      console.debug(JSON.stringify({ level: 'debug', message, ...meta, timestamp: new Date().toISOString() }));
    }
  }

  info(message: string, meta?: object): void {
    if (this.level <= LEVELS.info) {
      console.info(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() }));
    }
  }

  warn(message: string, meta?: object): void {
    if (this.level <= LEVELS.warn) {
      console.warn(JSON.stringify({ level: 'warn', message, ...meta, timestamp: new Date().toISOString() }));
    }
  }

  error(message: string, meta?: object): void {
    if (this.level <= LEVELS.error) {
      console.error(JSON.stringify({ level: 'error', message, ...meta, timestamp: new Date().toISOString() }));
    }
  }
}
