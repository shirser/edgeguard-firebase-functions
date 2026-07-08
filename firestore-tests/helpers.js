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

// Exact command shape Home App writes on create (DeleteCameraScreen.kt) —
// UNPAIR is the only type/status value the client ever produces.
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
