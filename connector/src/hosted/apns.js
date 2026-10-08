import { createAPNs } from "../push.js";
export function createHostedAPNs(env = process.env, factory = createAPNs) {
  const baseEnvironment = env.APNS_ENVIRONMENT ?? "sandbox";
  if (!["sandbox", "production", "both"].includes(baseEnvironment))
    throw new Error("APNS_ENVIRONMENT must identify the key scope.");
  const base = factory({
    ...env,
    APNS_ALERT_TITLE: "Rook approved your request",
  });
  const productionFields = [
    "APNS_PRODUCTION_KEY_ID",
    "APNS_PRODUCTION_TEAM_ID",
    "APNS_PRODUCTION_PRIVATE_KEY",
  ];
  const hasProduction = productionFields.some((key) => Boolean(env[key]));
  if (hasProduction && !productionFields.every((key) => Boolean(env[key])))
    throw new Error("Configure every production APNs credential field.");
  const production = hasProduction
    ? factory({
        ...env,
        APNS_KEY_ID: env.APNS_PRODUCTION_KEY_ID,
        APNS_TEAM_ID: env.APNS_PRODUCTION_TEAM_ID,
        APNS_PRIVATE_KEY: env.APNS_PRODUCTION_PRIVATE_KEY,
        APNS_ALERT_TITLE: "Rook approved your request",
      })
    : null;
  const sandboxSender = ["sandbox", "both"].includes(baseEnvironment)
    ? base
    : null;
  const productionSender =
    production ??
    (["production", "both"].includes(baseEnvironment) ? base : null);
  if (!sandboxSender && !productionSender) return null;
  const send = async (device, alert, expiry) => {
    const sender =
      device.environment === "sandbox"
        ? sandboxSender
        : device.environment === "production"
          ? productionSender
          : null;
    return sender
      ? sender(device, alert, expiry)
      : { accepted: false, status: 503, reason: "UnconfiguredEnvironment" };
  };
  send.configured = {
    sandbox: Boolean(sandboxSender),
    production: Boolean(productionSender),
  };
  return send;
}
