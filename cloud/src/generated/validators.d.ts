// Types for the generated standalone ajv validators (see scripts/gen-validators.mjs).
export interface ValidationError {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  message?: string;
}
export interface ValidateFn {
  (data: unknown): boolean;
  errors?: ValidationError[] | null;
}
export const validateSignedEnvelope: ValidateFn;
export const validateSignedBody: ValidateFn;
export const validatePolicy: ValidateFn;
export const validateCommand: ValidateFn;
export const validateCommandAck: ValidateFn;
export const validateEvent: ValidateFn;
export const validateEventBatch: ValidateFn;
export const validateInventory: ValidateFn;
export const validateEnrollRequest: ValidateFn;
export const validateEnrollStartRequest: ValidateFn;
export const validateMasterRegister: ValidateFn;
export const validateMasterRegisterWithClaim: ValidateFn;
export const validatePushSubscribe: ValidateFn;
export const validateDeviceState: ValidateFn;
export const validateWsDeviceMessage: ValidateFn;
