import { createContext, useState, useContext, useEffect, useRef } from "react";
import api, { setAccessToken } from "../api/axios";
import axios from "axios";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // true while we check for an existing session

  // On app load, try to silently refresh — if the httpOnly cookie is still
  // valid, this logs the user back in without them re-entering credentials.
  const didRun = useRef(false);

  useEffect(() => {
    if (didRun.current) return;
    didRun.current = true;

    const tryRefresh = async () => {
      try {
        const { data } = await axios.post(
          "http://localhost:5001/api/auth/refresh",
          {},
          { withCredentials: true },
        );
        setAccessToken(data.token);
        const me = await api.get("/auth/me");
        setUser(me.data);
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };
    tryRefresh();
  }, []);

  const login = async (email, password) => {
    const { data } = await api.post("/auth/login", { email, password });
    setAccessToken(data.token);
    setUser(data.user);
  };

  const register = async (username, email, password) => {
    const { data } = await api.post("/auth/register", {
      username,
      email,
      password,
    });
    setAccessToken(data.token);
    setUser(data.user);
  };

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // even if the request fails, clear local state
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
