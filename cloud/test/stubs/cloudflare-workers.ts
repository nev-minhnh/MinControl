// Node-side stand-in for the "cloudflare:workers" runtime module (unit tests only).
export class DurableObject<Env = unknown> {
  ctx: unknown;
  env: Env;
  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
