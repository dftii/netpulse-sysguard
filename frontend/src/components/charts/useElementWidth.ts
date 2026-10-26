/** Tracks the content-box width of an element with a ResizeObserver. */

import { useLayoutEffect, useRef, useState, type RefObject } from "react";

export function useElementWidth<T extends HTMLElement>(): { ref: RefObject<T | null>; width: number } {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    setWidth(Math.floor(element.getBoundingClientRect().width));
    if (typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[entries.length - 1];
      if (entry) setWidth(Math.floor(entry.contentRect.width));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return { ref, width };
}
