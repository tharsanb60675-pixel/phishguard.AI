package ai.phishguard.companion

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.phishguard.companion.data.models.QRScanModel
import ai.phishguard.companion.networking.SseClient
import ai.phishguard.companion.notifications.NotificationHelper

class MainActivity : ComponentActivity() {
    private lateinit var notificationHelper: NotificationHelper
    private lateinit var sseClient: SseClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        notificationHelper = NotificationHelper(this)

        setContent {
            PhishGuardApp(
                onInitSse = { onScan, onState ->
                    sseClient = SseClient(
                        serverBaseUrl = "http://10.0.2.2:8000/api/v1",
                        onScanReceived = { scan ->
                            onScan(scan)
                            notificationHelper.dispatchThreatAlert(scan)
                        },
                        onConnectionStateChanged = onState
                    )
                    sseClient.connect()
                }
            )
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::sseClient.isInitialized) {
            sseClient.disconnect()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PhishGuardApp(onInitSse: ((QRScanModel) -> Unit, (Boolean) -> Unit) -> Unit) {
    var isConnected by remember { mutableStateOf(false) }
    var latestScan by remember { mutableStateOf<QRScanModel?>(null) }
    val scanHistory = remember { mutableStateListOf<QRScanModel>() }

    LaunchedEffect(Unit) {
        onInitSse(
            { scan ->
                latestScan = scan
                scanHistory.add(0, scan)
            },
            { state ->
                isConnected = state
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("🛡️ PhishGuard.AI", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 18.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Shield", color = Color(0xFF38BDF8), fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                },
                actions = {
                    Surface(
                        color = if (isConnected) Color(0x2210B981) else Color(0x22F43F5E),
                        shape = RoundedCornerShape(12.dp),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (isConnected) Color(0xFF10B981) else Color(0xFFF43F5E)
                        ),
                        modifier = Modifier.padding(end = 12.dp)
                    ) {
                        Text(
                            text = if (isConnected) "● CONNECTED" else "○ CONNECTING",
                            color = if (isConnected) Color(0xFF10B981) else Color(0xFFF43F5E),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color(0xFF090D16))
            )
        },
        containerColor = Color(0xFF090D16)
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Live Shield Status Banner
            item {
                Surface(
                    color = Color(0xFF0F172A),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF1E293B)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("BACKGROUND SHIELD", color = Color(0xFF64748B), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                            Text("Real-Time Telemetry Sync", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        }
                        Text("ACTIVE", color = Color(0xFF38BDF8), fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                    }
                }
            }

            // Latest QR Scan Card
            item {
                Text("LATEST QR THREAT DETECTION", color = Color(0xFF64748B), fontSize = 11.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                Spacer(modifier = Modifier.height(6.dp))

                latestScan?.let { scan ->
                    Surface(
                        color = Color(0xFF0F172A),
                        shape = RoundedCornerShape(16.dp),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            when (scan.severity) {
                                "CRITICAL" -> Color(0xFFF43F5E)
                                "SUSPICIOUS" -> Color(0xFFF59E0B)
                                else -> Color(0xFF10B981)
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Surface(
                                    color = when (scan.severity) {
                                        "CRITICAL" -> Color(0x33F43F5E)
                                        "SUSPICIOUS" -> Color(0x33F59E0B)
                                        else -> Color(0x3310B981)
                                    },
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text(
                                        text = scan.severity,
                                        color = when (scan.severity) {
                                            "CRITICAL" -> Color(0xFFF43F5E)
                                            "SUSPICIOUS" -> Color(0xFFF59E0B)
                                            else -> Color(0xFF10B981)
                                        },
                                        fontWeight = FontWeight.Black,
                                        fontSize = 11.sp,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                    )
                                }

                                Text(
                                    text = "${scan.threatScore.toInt()}/100",
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.ExtraBold
                                )
                            }

                            Text(
                                text = scan.classification,
                                color = Color(0xFFCBD5E1),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Surface(
                                color = Color(0xFF090D16),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = scan.payload,
                                    color = Color(0xFF38BDF8),
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.padding(8.dp),
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }

                            if (scan.analysisReasons.isNotEmpty()) {
                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text("SECURITY EXPLANATION", color = Color(0xFF64748B), fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                    scan.analysisReasons.take(2).forEach { reason ->
                                        Text("• $reason", color = Color(0xFF94A3B8), fontSize = 11.sp)
                                    }
                                }
                            }

                            if (scan.isBlocked) {
                                Surface(
                                    color = Color(0x22F43F5E),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        text = "🛑 Automatically Blocked by Laptop Shield",
                                        color = Color(0xFFFECDD3),
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(8.dp)
                                    )
                                }
                            }
                        }
                    }
                } ?: Surface(
                    color = Color(0xFF0F172A),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF1E293B)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Waiting for QR threat scan from laptop browser...",
                        color = Color(0xFF64748B),
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(24.dp)
                    )
                }
            }

            // History Section
            if (scanHistory.isNotEmpty()) {
                item {
                    Text("RECENT SCANS", color = Color(0xFF64748B), fontSize = 11.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                }
                items(scanHistory) { item ->
                    Surface(
                        color = Color(0xFF0F172A),
                        shape = RoundedCornerShape(12.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF1E293B)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.domain ?: item.payload,
                                    color = Color(0xFF38BDF8),
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${item.severity} • ${item.classification}",
                                    color = Color(0xFF64748B),
                                    fontSize = 10.sp
                                )
                            }
                            Text(
                                text = "${item.threatScore.toInt()}",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
