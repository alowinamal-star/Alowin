import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Minimal async data hook: runs a loader, exposes {data, loading, error, reload}.
 * Keeps every page bound to real API responses without a state library.
 */
export function useAsync(loader, deps = [], { immediate = true } = {}) {
  const [state, setState] = useState({ data: null, loading: immediate, error: "" });
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const data = await loader();
      if (mounted.current) setState({ data, loading: false, error: "" });
      return data;
    } catch (err) {
      if (mounted.current) setState({ data: null, loading: false, error: err.message || "Request failed." });
      return null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (immediate) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, immediate]);

  return { ...state, reload: run, setData: (data) => setState((prev) => ({ ...prev, data })) };
}

/** Transient success/error banner state. */
export function useNotice(timeout = 6000) {
  const [notice, setNotice] = useState(null);
  useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(null), timeout);
    return () => clearTimeout(timer);
  }, [notice, timeout]);
  return {
    notice,
    success: (message) => setNotice({ type: "success", message }),
    error: (message) => setNotice({ type: "error", message }),
    clear: () => setNotice(null),
  };
}
