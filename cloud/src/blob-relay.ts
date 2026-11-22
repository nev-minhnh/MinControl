// On-demand screenshot relay state (API.md section 9). Pending master requests live in memory only: the
// waiting master request keeps the Durable Object alive, and the bytes are never persisted.
import { ulid } from "./lib/ulid";

export const BLOB_TIMEOUT_MS = 25_000;

export type BlobResult =
  | { status: "ok"; bytes: Uint8Array }
  | { status: "offline" }
  | { status: "timeout" }
  | { status: "missing" };

interface Pending {
  key: string;
  resolve: (r: BlobResult) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class BlobRelay {
  private readonly pending = new Map<string, Pending>();

  constructor(private readonly timeoutMs: number = BLOB_TIMEOUT_MS) {}

  get size(): number {
    return this.pending.size;
  }

  /**
   * `send(frame)` pushes the blob_request frame to the device and returns false when there is no
   * authenticated socket (-> offline). Resolves when the device answers or the timeout fires.
   */
  request(key: string, send: (frame: string) => boolean): Promise<BlobResult> {
    const reqId = ulid();
    return new Promise<BlobResult>((resolve) => {
      const timer = setTimeout(() => this.settle(reqId, { status: "timeout" }), this.timeoutMs);
      this.pending.set(reqId, { key, resolve, timer });
      let sent = false;
      try {
        sent = send(JSON.stringify({ t: "blob_request", reqId, key }));
      } catch {
        sent = false;
      }
      if (!sent) this.settle(reqId, { status: "offline" });
    });
  }

  /** Device uploaded the bytes. False = unknown/expired reqId (or key mismatch) -> caller answers 410. */
  resolveBytes(reqId: string, key: string, bytes: Uint8Array): boolean {
    const p = this.pending.get(reqId);
    if (!p || p.key !== key) return false;
    return this.settle(reqId, { status: "ok", bytes });
  }

  /** Device reported `blob_missing`. */
  resolveMissing(reqId: string): boolean {
    return this.settle(reqId, { status: "missing" });
  }

  /** Fails every waiting request (socket closed / device revoked). */
  failAll(status: "offline"): void {
    for (const id of [...this.pending.keys()]) this.settle(id, { status });
  }

  private settle(reqId: string, r: BlobResult): boolean {
    const p = this.pending.get(reqId);
    if (!p) return false;
    this.pending.delete(reqId);
    clearTimeout(p.timer);
    p.resolve(r);
    return true;
  }
}
