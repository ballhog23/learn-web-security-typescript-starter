import { verifySync } from "otplib";
import type { DatabaseSync } from "node:sqlite";

const TOTP_PERIOD_SECONDS = 30;

export function verifyTotpCode(code: string, secret: string): boolean {
  if (!code) {
    return false;
  }

  try {
    return verifySync({
      secret,
      token: code,
    }).valid;
  } catch {
    return false;
  }
}

export function consumeTotpTimeStep(
  db: DatabaseSync,
  userId: number,
  timeStep: number,
): boolean {
  const result = db
    .prepare(
      `UPDATE users
       SET last_totp_step = ?
       WHERE id = ?
         AND (last_totp_step IS NULL OR last_totp_step < ?)`,
    )
    .run(timeStep, userId, timeStep);

  return result.changes === 1;
}

export function verifyAndConsumeTotpCode(
  db: DatabaseSync,
  userId: number,
  code: string,
  secret: string,
): boolean {
  if (!verifyTotpCode(code, secret))
    return false;
  // creates a 30 second window for the TOTP code based on the unix epoch time in seconds.
  const timeStep = Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);
  return consumeTotpTimeStep(db, userId, timeStep);
}
