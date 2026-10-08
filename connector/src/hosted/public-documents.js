export function publicDocuments(app, supportEmail) {
  app.get("/privacy", (_req, res) =>
    res
      .type("text/plain")
      .send(
        `Rook privacy\n\nRook helps you choose intentional access to selected apps. Your Screen Time app selection stays on your phone. We store your Apple account identifier and optional display name, registered device identifiers and push tokens, access grants/cooldowns, and the request messages you choose to send. Subscription transactions are stored when paid billing is enabled. Brief keyed network-address digests and request counts help enforce abuse and cost limits; raw IP addresses are not retained by the application.\n\nAI processing is optional and requires your consent. When you use Ask Rook, your request and limited recent conversation context are sent through Vercel AI Gateway to the configured model provider to assess your purpose and exit plan. App selections and credentials are not included. Avoid sensitive details. The AI may be wrong. Code enforces the access limit and cooldown.\n\nConversation history is available for up to 30 days. Scheduled cleanup removes older conversation and request text from the active database. Clear conversation history or withdraw AI consent in Settings. Timing facts are retained to preserve your cooldown. Deleting your account removes your owned records and revokes connections. AI provider retention is governed by the provider's settings and terms; we do not claim zero provider retention without verifying it.\n\nRook uses individual Screen Time authorization. You can revoke permission or uninstall the app; it is a voluntary boundary.\n\nSupport: ${supportEmail ?? "Support contact is being configured for the beta."}\n`,
      ),
  );
  app.get("/support", (_req, res) =>
    res
      .type("text/plain")
      .send(
        `Rook support\n\n${supportEmail ?? "Support contact is being configured for the beta."}\n\nFor access that has not started, reopen Rook to sync. An approval is not an unlock. For privacy controls, open Settings to clear history, withdraw consent, disconnect an agent, or delete your account.\n`,
      ),
  );
}
