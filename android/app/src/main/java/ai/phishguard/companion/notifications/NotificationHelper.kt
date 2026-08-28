package ai.phishguard.companion.notifications

import ai.phishguard.companion.MainActivity
import ai.phishguard.companion.data.models.QRScanModel
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class NotificationHelper(private val context: Context) {
    companion object {
        const val CHANNEL_ID = "phishguard_threat_alerts"
        const val CHANNEL_NAME = "High-Risk Threat Alerts"
    }

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical alerts when malicious or high-risk QR codes are detected on paired laptop"
                enableVibration(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    fun dispatchThreatAlert(scan: QRScanModel) {
        // Only dispatch for suspicious, high risk, or critical threats
        if (scan.severity != "CRITICAL" && scan.severity != "HIGH RISK" && scan.severity != "SUSPICIOUS") {
            return
        }

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("🚨 ${scan.severity} QR Detected on Laptop")
            .setContentText("Threat Score: ${scan.threatScore}/100 (${scan.classification}). Destination: ${scan.domain ?: "Unknown"}")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "Phishing indicators detected on your laptop browser.\n" +
                "Target: ${scan.payload}\n" +
                "Score: ${scan.threatScore}/100\n" +
                (scan.analysisReasons.firstOrNull() ?: "")
            ))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        try {
            NotificationManagerCompat.from(context).notify(scan.scanId, builder.build())
        } catch (e: SecurityException) {
            e.printStackTrace()
        }
    }
}
