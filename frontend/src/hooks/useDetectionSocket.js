import { useEffect, useRef, useState } from "react";

import { buildWebSocketUrl } from "../lib/api";

export function useDetectionSocket({ enabled = true, onDetection, throttleMs = 80 }) {
  const onDetectionRef = useRef(onDetection);
  const reconnectTimerRef = useRef(null);
  const socketRef = useRef(null);
  const frameRef = useRef(null);
  const lastDispatchAtRef = useRef(0);
  const pendingPayloadsRef = useRef([]);
  const [connectionState, setConnectionState] = useState("disconnected");
  const [lastPacketAt, setLastPacketAt] = useState(null);

  useEffect(() => {
    onDetectionRef.current = onDetection;
  }, [onDetection]);

  useEffect(() => {
    if (!enabled) {
      setConnectionState("disabled");
      return undefined;
    }

    let closed = false;

    function clearReconnectTimer() {
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    }

    function clearFrame() {
      if (frameRef.current) {
        window.cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      }
    }

    function flushPacket() {
      frameRef.current = null;
      if (!pendingPayloadsRef.current.length) {
        return;
      }
      const now = Date.now();
      if (throttleMs > 0 && now - lastDispatchAtRef.current < throttleMs) {
        frameRef.current = window.requestAnimationFrame(flushPacket);
        return;
      }
      lastDispatchAtRef.current = now;
      const payload = pendingPayloadsRef.current.shift();
      onDetectionRef.current?.(payload);
      if (pendingPayloadsRef.current.length) {
        frameRef.current = window.requestAnimationFrame(flushPacket);
      }
    }

    function connect() {
      clearReconnectTimer();
      clearFrame();
      setConnectionState("connecting");
      const socket = new WebSocket(buildWebSocketUrl("/ws/detections"));
      socketRef.current = socket;

      socket.onopen = () => {
        if (!closed) {
          setConnectionState("open");
        }
      };

      socket.onmessage = (event) => {
        if (closed) {
          return;
        }
        try {
          const payload = JSON.parse(event.data);
          setLastPacketAt(payload?.timestamp || new Date().toISOString());
          pendingPayloadsRef.current.push(payload);
          if (!frameRef.current) {
            frameRef.current = window.requestAnimationFrame(flushPacket);
          }
        } catch (error) {
          console.error("Failed to parse detection packet", error);
        }
      };

      socket.onerror = () => {
        if (!closed) {
          setConnectionState("error");
        }
      };

      socket.onclose = () => {
        if (socketRef.current === socket) {
          socketRef.current = null;
        }
        if (closed) {
          return;
        }
        setConnectionState("closed");
        reconnectTimerRef.current = window.setTimeout(connect, 2000);
      };
    }

    connect();

    return () => {
      closed = true;
      clearReconnectTimer();
      clearFrame();
      pendingPayloadsRef.current = [];
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [enabled, throttleMs]);

  return { connectionState, lastPacketAt };
}
