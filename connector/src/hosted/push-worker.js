export class HostedPushWorker {
  constructor({ store, send, clock = () => Date.now() }) {
    this.store = store;
    this.send = send;
    this.clock = clock;
    this.running = false;
  }
  async init() {
    await this.store.pool.query(
      "ALTER TABLE gk_push_jobs ADD COLUMN IF NOT EXISTS silent_at timestamptz",
    );
  }
  async tick() {
    if (this.running || !this.send) return;
    this.running = true;
    try {
      for (const job of await this.store.claimPushJobs(20)) {
        try {
          let expiry = this.clock() + 300000;
          if (job.event === "approve") {
            const pass = (
              await this.store.pool.query(
                "SELECT * FROM gk_grants WHERE id=$1 AND user_id=$2 AND device_id=$3",
                [job.grant_id, job.user_id, job.device_id],
              )
            ).rows[0];
            if (
              !pass ||
              pass.revoked_at ||
              pass.redeemed_at ||
              new Date(pass.valid_until).getTime() <= this.clock()
            ) {
              await this.store.completePushJob(job);
              continue;
            }
            expiry = new Date(pass.valid_until).getTime();
          }
          const alert = job.event === "approve" && Boolean(job.silent_at);
          const result = await this.send(
            { token: job.apns_token, environment: job.apns_environment },
            alert,
            expiry,
          );
          if (result.accepted) {
            if (job.event === "approve" && !alert)
              await this.store.pool.query(
                "UPDATE gk_push_jobs SET silent_at=$1,available_at=$2,lease_until=NULL,lease_token=NULL WHERE id=$3 AND lease_token=$4 AND completed_at IS NULL AND user_id=$5 AND device_id=$6",
                [
                  new Date(this.clock()),
                  new Date(this.clock() + 15000),
                  job.id,
                  job.lease_token,
                  job.user_id,
                  job.device_id,
                ],
              );
            else await this.store.completePushJob(job);
          } else if (
            result.status === 410 ||
            (result.status === 400 &&
              ["BadDeviceToken", "DeviceTokenNotForTopic"].includes(
                result.reason,
              ))
          )
            await this.store.completePushJob(job, { invalidToken: true });
          else await this.store.retryPushJob(job);
        } catch (error) {
          // Deletion can remove the account/job while delivery is in flight.
          if (error.code !== "not_found") await this.store.retryPushJob(job);
        }
      }
    } finally {
      this.running = false;
    }
  }
}
