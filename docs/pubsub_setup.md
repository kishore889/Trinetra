# TRINETRA — Gmail Watch & Cloud Pub/Sub Push Subscription

TRINETRA uses **Gmail Watch + Google Cloud Pub/Sub** for real-time, event-driven email ingestion without continuous polling overhead.

---

## Ingestion Architecture

```
User Inbox ──▶ Gmail Server ──▶ Gmail Watch Expiration (7 days)
                                       │
                                       ▼
                             Google Cloud Pub/Sub Topic
                                       │
                                       ▼ (Push Webhook)
                             Cloud Run Webhook Endpoint
                             (/api/v1/monitor/pubsub/push)
                                       │
                                       ▼
                             Gmail History API Sync
                             (Fetch new message IDs)
                                       │
                                       ▼
                             TRINETRA Phishing Pipeline
```

---

## Google Cloud Pub/Sub Setup Steps

1. Create a Pub/Sub topic named `gmail-notifications`:
   ```bash
   gcloud pubsub topics create gmail-notifications
   ```
2. Grant Gmail service account permission to publish to the topic:
   - Service account: `gmail-api-push@system.gserviceaccount.com`
   - Role: `Pub/Sub Publisher`
3. Create a Push Subscription:
   ```bash
   gcloud pubsub subscriptions create trinetra-gmail-sub \
       --topic=gmail-notifications \
       --push-endpoint=https://your-api-domain.com/api/v1/monitor/pubsub/push
   ```
4. Set environment variables in `.env`:
   ```env
   GOOGLE_CLOUD_PROJECT=your-gcp-project-id
   GOOGLE_PUBSUB_TOPIC=projects/your-gcp-project-id/topics/gmail-notifications
   ```

---

## Polling Fallback

If Pub/Sub is not configured or during local offline development, TRINETRA seamlessly degrades to a periodic local polling scheduler (`app/services/gmail_monitor.py`) every 30 seconds, ensuring uninterrupted protection.
