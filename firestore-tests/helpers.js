import { readFileSync } from "node:fs";
import { initializeTestEnvironment } from "@firebase/rules-unit-testing";
import { doc, setDoc } from "firebase/firestore";

export const PROJECT_ID = "demo-edgeguard-rules-test";
export const CAMERA_ID = "camera-1";
export const HOME_UID = "home-owner-uid";
export const CAMERA_UID = "camera-auth-uid";
export const STRANGER_UID = "stranger-uid";

export async function createTestEnv() {
  return initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules: readFileSync("firestore.rules", "utf8"),
      host: "127.0.0.1",
      port: 8080,
    },
  });
}

// Seeds cameraClaims/{CAMERA_ID} the way claimCameraForUser (functions/src/index.ts)
// writes it, bypassing rules — cameraClaims is function-only from the client's side.
export async function seedClaim(testEnv, overrides = {}) {
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore(), "cameraClaims", CAMERA_ID), {
      uid: HOME_UID,
      cameraAuthUid: CAMERA_UID,
      claimedAt: new Date(),
      ...overrides,
    });
  });
}

export async function seedDoc(testEnv, path, data) {
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore(), ...path), data);
  });
}

// Same as seedDoc but merges onto any existing document instead of replacing
// it — mirrors createCameraPairingSession's `{ merge: true }` write onto
// pairingState/current, which only touches cameraAuthUid/pairingRequestedAt
// and leaves any pre-existing fields (e.g. a stale status:"unpaired") intact.
export async function mergeDoc(testEnv, path, data) {
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore(), ...path), data, { merge: true });
  });
}

// Exact command shape Home App writes on create (DeleteCameraScreen.kt) —
// UNPAIR and CONFIRM_PLACEMENT are the only type values the client ever
// produces, and "pending" the only initial status.
export function validCommand(overrides = {}) {
  return {
    type: "UNPAIR",
    status: "pending",
    createdAt: new Date(),
    createdBy: HOME_UID,
    homeDeviceId: "home-device-1",
    cameraDeviceId: CAMERA_ID,
    ...overrides,
  };
}

export function homeDb(testEnv) {
  return testEnv.authenticatedContext(HOME_UID).firestore();
}

export function cameraDb(testEnv) {
  return testEnv.authenticatedContext(CAMERA_UID).firestore();
}

export function strangerDb(testEnv) {
  return testEnv.authenticatedContext(STRANGER_UID).firestore();
}
