package io.github.nevminhnh.mincontrol.master.live

import io.github.nevminhnh.mincontrol.master.data.api.MasterApi
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/** OkHttp WebSocket to `GET /v1/master/live?deviceId=` (signed upgrade request, ping every 25 s). */
class OkLiveConnector(private val api: MasterApi) : LiveConnector {
    override fun connect(deviceId: String, listener: LiveListener): LiveSocket {
        val ws = api.openLive(deviceId, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) = listener.onOpen()
            override fun onMessage(webSocket: WebSocket, text: String) = listener.onMessage(text)
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { webSocket.close(code, null); listener.onClosed() }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = listener.onClosed()
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = listener.onClosed()
        })
        return object : LiveSocket { override fun close() { ws.cancel() } }
    }
}
