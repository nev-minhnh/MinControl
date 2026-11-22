import type { DeviceHub } from "./device-hub";

export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;
  DEVICE_HUB: DurableObjectNamespace<DeviceHub>;
  /** Secret that allows POST /v1/master/register (unset = registration disabled). */
  ADMIN_BOOTSTRAP_SECRET?: string;
  /** Firebase service-account JSON (one line) for FCM HTTP v1 (unset = pushes skipped). */
  FCM_SERVICE_ACCOUNT_JSON?: string;
  /** HMAC-SHA256 key for device upload tokens (required for device uploads). */
  UPLOAD_TOKEN_SECRET?: string;
}
