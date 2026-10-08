export class HostedError extends Error {
  constructor(message, code = "invalid_request", status = 400) {
    super(message);
    this.name = "HostedError";
    this.code = code;
    this.status = status;
  }
}
export class PolicyError extends HostedError {
  constructor(message) {
    super(message, "policy_denied", 409);
  }
}
export class AppleTokenError extends HostedError {
  constructor(appleError, authoritativeRevocation = false) {
    super(
      "Apple token validation failed.",
      "apple_token_rejected",
      authoritativeRevocation ? 401 : 503,
    );
    this.name = "AppleTokenError";
    this.appleError = appleError;
    this.authoritativeRevocation = authoritativeRevocation;
  }
}
