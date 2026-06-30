import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { onValueWritten } from "firebase-functions/v2/database";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";

admin.initializeApp();

export const enqueueCameraStatusNotification = onValueWritten(
  {
    ref: "cameraStatus/{cameraDeviceId}",
    region: "europe-west1",
  },
  async (event) => {
    const { cameraDeviceId } = event.params;
    const before = event.data.before.val();
    const after = event.data.after.val();

    const beforeConnectionState: string = before?.connectionState ?? "";
    const afterConnectionState: string = after?.connectionState ?? "";
    const beforeAppState: string = before?.appState ?? "";
    const afterAppState: string = after?.appState ?? "";

    const isAppClosed =
      beforeAppState === "running" && afterAppState === "stopped";

    const isOffline =
      beforeConnectionState === "connected" &&
      afterConnectionState === "disconnected" &&
      afterAppState !== "stopped";

    if (!isAppClosed && !isOffline) {
      logger.info("CAMERA_STATUS_SKIP", {
        cameraDeviceId,
        beforeAppState,
        afterAppState,
        beforeConnectionState,
        afterConnectionState,
      });
      return;
    }

    const db = admin.firestore();

    if (isOffline) {
      logger.info("CAMERA_OFFLINE_DETECTED", { cameraDeviceId });

      const offlineRef = db
        .collection("cameraLinks")
        .doc(cameraDeviceId)
        .collection("notificationQueue")
        .doc();

      await offlineRef.set({
        type: "camera_offline",
        title: "Camera offline",
        body: "Your Camera connection was lost.",
        status: "pending",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      logger.info("CAMERA_OFFLINE_QUEUE_CREATED", { eventId: offlineRef.id });
    }

    if (isAppClosed) {
      logger.info("CAMERA_APP_CLOSED_DETECTED", { cameraDeviceId });

      const appClosedRef = db
        .collection("cameraLinks")
        .doc(cameraDeviceId)
        .collection("notificationQueue")
        .doc();

      await appClosedRef.set({
        type: "camera_app_closed",
        title: "Camera app was closed",
        body: "Your Camera app was closed.",
        status: "pending",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      logger.info("CAMERA_APP_CLOSED_QUEUE_CREATED", {
        eventId: appClosedRef.id,
      });
    }
  }
);

export const sendNotificationOnCreate = onDocumentCreated(
  {
    document: "cameraLinks/{cameraDeviceId}/notificationQueue/{eventId}",
    region: "europe-west1",
  },
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;

    const data = snapshot.data();
    const { cameraDeviceId, eventId } = event.params;

    if (data.status !== "pending") {
      logger.info("Skip non-pending notification", {
        cameraDeviceId,
        eventId,
        status: data.status,
      });
      return;
    }

    const title = data.title;
    const body = data.body;

    if (!title || !body) {
      await snapshot.ref.update({
        status: "failed",
        error: "Missing title or body",
        failedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return;
    }

    const targetSnap = await admin
      .firestore()
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("notificationTarget")
      .doc("home")
      .get();

    const fcmToken = targetSnap.get("fcmToken");

    if (!fcmToken) {
      await snapshot.ref.update({
        status: "failed",
        error: "Missing Home FCM token",
        failedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return;
    }

    try {
      const messageId = await admin.messaging().send({
        token: fcmToken,
        notification: {
          title,
          body,
        },
        data: {
          type: String(data.type ?? ""),
          cameraDeviceId: String(cameraDeviceId),
          eventId: String(eventId),
          title: String(title),
          body: String(body),
        },
        android: {
          priority: "high",
          notification: {
            channelId: "edgeguard_alerts_v1",
            priority: "high",
            defaultSound: true,
            defaultVibrateTimings: true,
          },
        },
      });

      await snapshot.ref.update({
        status: "sent",
        sentAt: admin.firestore.FieldValue.serverTimestamp(),
        messageId,
      });

      logger.info("Push sent", { cameraDeviceId, eventId, messageId });
    } catch (error: any) {
      await snapshot.ref.update({
        status: "failed",
        error: error?.message ?? String(error),
        failedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      logger.error("Push failed", { cameraDeviceId, eventId, error });
    }
  }
);
