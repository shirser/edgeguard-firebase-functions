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

// Exact CONFIRM_PLACEMENT shape Home App writes (PlacementImageTransferInitiator) —
// same base fields as validCommand() plus the sessionId/transferId pair that ties the
// command to the webrtcSessions doc and the command doc id created for that transfer.
export function validConfirmPlacementCommand(overrides = {}) {
  return validCommand({
    type: "CONFIRM_PLACEMENT",
    sessionId: "session-1",
    transferId: "transfer-1",
    ...overrides,
  });
}

// Exact shape the Home App will write on session create — status always
// starts at "waiting_for_offer" with no SDP attached yet (see
// firestore.rules' webrtcSessions match block for the lifecycle).
export function validSession(overrides = {}) {
  return {
    cameraDeviceId: CAMERA_ID,
    homeDeviceId: "home-device-1",
    createdBy: HOME_UID,
    purpose: "PLACEMENT_IMAGE",
    status: "waiting_for_offer",
    offerSdp: null,
    offerType: null,
    answerSdp: null,
    answerType: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    ...overrides,
  };
}

export function validCandidate(overrides = {}) {
  return {
    sdpMid: "0",
    sdpMLineIndex: 0,
    candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 12345 typ host",
    createdAt: new Date(),
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
