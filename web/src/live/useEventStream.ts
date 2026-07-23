// SPDX-License-Identifier: Apache-2.0 OR MIT
import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";
import type { EventKind } from "../api/event-types";
import { EventStream, eventKindFilter, type StreamOptions, type StreamSnapshot } from "./stream";

export interface LiveStreamState extends StreamSnapshot {
  /** Buffer filtered for display (kind filter applied client-side). */
  visible: StreamSnapshot["events"];
  togglePause: () => void;
  restart: () => void;
  clearBuffer: () => void;
}

/**
 * Owns one EventStream per mount. The stream keeps running across
 * re-renders; unmount closes the socket.
 */
export function useEventStream(
  kindFilter: EventKind | "all",
  opts: StreamOptions = {},
): LiveStreamState {
  const streamRef = useRef<EventStream | null>(null);
  if (streamRef.current === null) {
    streamRef.current = new EventStream(opts);
  }
  const stream = streamRef.current;

  const subscribe = useCallback((onChange: () => void) => stream.subscribe(onChange), [stream]);
  const snapshot = useSyncExternalStore(subscribe, () => stream.getSnapshot());

  useEffect(() => {
    stream.start();
    return () => {
      stream.stop();
    };
  }, [stream]);

  const togglePause = useCallback(() => {
    const s = stream.getSnapshot().status;
    if (s === "paused") stream.resume();
    else if (s !== "closed" && s !== "failed") stream.pause();
  }, [stream]);

  const restart = useCallback(() => {
    stream.clear();
    stream.start();
  }, [stream]);

  const clearBuffer = useCallback(() => {
    stream.clear();
  }, [stream]);

  return {
    ...snapshot,
    visible: eventKindFilter(snapshot.events, kindFilter),
    togglePause,
    restart,
    clearBuffer,
  };
}
