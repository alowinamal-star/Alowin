import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, getToken, setToken } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(Boolean(getToken()));
  const [error, setError] = useState("");

  const loadUser = useCallback(async () => {
    if (!getToken()) {
      setUser(null);
      setLoading(false);
      return null;
    }
    try {
      const me = await api.me();
      setUser(me.user || me);
      return me.user || me;
    } catch (err) {
      setToken("");
      setUser(null);
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();
    const onUnauthorized = () => setUser(null);
    window.addEventListener("promptshield:unauthorized", onUnauthorized);
    return () => window.removeEventListener("promptshield:unauthorized", onUnauthorized);
  }, [loadUser]);

  const login = useCallback(async (email, password) => {
    setError("");
    const result = await api.login(email, password);
    setToken(result.token);
    setUser(result.user);
    return result.user;
  }, []);

  const register = useCallback(async (payload) => {
    setError("");
    const result = await api.register(payload);
    setToken(result.token);
    setUser(result.user);
    return result.user;
  }, []);

  const logout = useCallback(() => {
    setToken("");
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, error, login, register, logout, refresh: loadUser }),
    [user, loading, error, login, register, logout, loadUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
