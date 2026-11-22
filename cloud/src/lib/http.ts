// JSON responses, the error shape `{"error","message"}` and bounded body reading.
import type { ValidateFn } from "../generated/validators";
import { fromUtf8 } from "./encoding";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
    readonly details?: unknown,
  ) {
    super(message ?? code);
  }
}

export function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return Response.json(body, { status, headers });
}

export function noContent(): Response {
  return new Response(null, { status: 204 });
}

export function errorResponse(status: number, code: string, message?: string, details?: unknown): Response {
  const body: Record<string, unknown> = { error: code, message: message ?? code };
  if (details !== undefined) body.details = details;
  return json(body, status);
}

export const badRequest = (message: string, details?: unknown) => new HttpError(400, "invalid_body", message, details);
export const notFound = (what = "not_found") => new HttpError(404, "not_found", what);

/** Reads the body as bytes, refusing anything larger than `maxBytes` (413). */
export async function readBytes(request: Request, maxBytes: number): Promise<Uint8Array> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > maxBytes) {
    throw new HttpError(413, "too_large", `body exceeds ${maxBytes} bytes`);
  }
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, "too_large", `body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export function parseJsonBytes(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(fromUtf8(bytes));
  } catch {
    throw new HttpError(400, "invalid_json", "body is not valid UTF-8 JSON");
  }
}

/** Validates `data` with a precompiled schema validator or throws 400 with the ajv errors. */
export function validateOrThrow<T>(validate: ValidateFn, data: unknown, what: string): T {
  if (!validate(data)) {
    const details = (validate.errors ?? []).slice(0, 5).map((e) => ({ path: e.instancePath, message: e.message }));
    throw badRequest(`${what} does not match the schema`, details);
  }
  return data as T;
}
