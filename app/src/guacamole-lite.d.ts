// Tipi minimi per guacamole-lite 1.2.0 (il pacchetto non li fornisce)
declare module "guacamole-lite" {
  import { EventEmitter } from "node:events";
  export interface ClientConnection {
    connectionId: number;
    connectionSettings: Record<string | symbol, any>;
  }
  export default class GuacamoleLite extends EventEmitter {
    constructor(
      wsOptions: Record<string, unknown>,
      guacdOptions: { host: string; port: number },
      clientOptions: Record<string, unknown>,
      callbacks?: {
        processConnectionSettings?: (
          settings: Record<string | symbol, any>,
          callback: (err: Error | undefined, settings?: Record<string | symbol, any>) => void,
        ) => void;
      },
    );
    close(): void;
    on(event: "open", listener: (connection: ClientConnection) => void): this;
    on(event: "close", listener: (connection: ClientConnection, error?: Error) => void): this;
    on(event: "error", listener: (connection: ClientConnection, error: Error) => void): this;
  }
}
