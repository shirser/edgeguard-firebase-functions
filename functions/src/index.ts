import { onDocumentCreated } from "firebase-functions/v2/firestore";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";

admin.initializeApp();

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
