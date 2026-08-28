package ai.phishguard.companion.data.models

import com.google.gson.annotations.SerializedName

data class QRScanModel(
    @SerializedName("scan_id") val scanId: Int,
    @SerializedName("payload") val payload: String,
    @SerializedName("qr_type") val qrType: String,
    @SerializedName("domain") val domain: String?,
    @SerializedName("threat_score") val threatScore: Float,
    @SerializedName("severity") val severity: String, // "SAFE", "LOW RISK", "SUSPICIOUS", "HIGH RISK", "CRITICAL"
    @SerializedName("classification") val classification: String,
    @SerializedName("confidence") val confidence: Float,
    @SerializedName("analysis_reasons") val analysisReasons: List<String>,
    @SerializedName("is_blocked") val isBlocked: Boolean,
    @SerializedName("page_url") val pageUrl: String?,
    @SerializedName("page_title") val pageTitle: String?,
    @SerializedName("timestamp") val timestamp: String
)

data class PairingConfirmRequest(
    @SerializedName("pairing_code") val pairingCode: String,
    @SerializedName("device_name") val deviceName: String = "Android Mobile",
    @SerializedName("device_id") val deviceId: String,
    @SerializedName("device_type") val deviceType: String = "android"
)

data class PairingConfirmResponse(
    @SerializedName("status") val status: String,
    @SerializedName("message") val message: String,
    @SerializedName("device") val device: PairedDeviceInfo
)

data class PairedDeviceInfo(
    @SerializedName("id") val id: Int,
    @SerializedName("device_name") val deviceName: String,
    @SerializedName("auth_token") val authToken: String
)
