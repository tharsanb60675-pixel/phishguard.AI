package ai.phishguard.companion.networking

import ai.phishguard.companion.data.models.QRScanModel
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.*
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import java.util.concurrent.TimeUnit

class SseClient(
    private val serverBaseUrl: String = "http://10.0.2.2:8000/api/v1",
    private val onScanReceived: (QRScanModel) -> Unit,
    private val onConnectionStateChanged: (Boolean) -> Unit
) {
    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private var eventSource: EventSource? = null
    private val gson = Gson()

    fun connect(authToken: String? = null) {
        val url = "$serverBaseUrl/devices/events" + if (authToken != null) "?token=$authToken" else ""
        val request = Request.Builder()
            .url(url)
            .header("Accept", "text/event-stream")
            .build()

        eventSource = EventSources.createFactory(client).newEventSource(request, object : EventSourceListener() {
            override fun onOpen(eventSource: EventSource, response: Response) {
                onConnectionStateChanged(true)
            }

            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                try {
                    val jsonObj = gson.fromJson(data, JsonObject::class.java)
                    if (jsonObj.has("scan")) {
                        val scanModel = gson.fromJson(jsonObj.get("scan"), QRScanModel::class.java)
                        onScanReceived(scanModel)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }

            override fun onClosed(eventSource: EventSource) {
                onConnectionStateChanged(false)
            }

            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                onConnectionStateChanged(false)
            }
        })
    }

    fun disconnect() {
        eventSource?.cancel()
        eventSource = null
    }
}
