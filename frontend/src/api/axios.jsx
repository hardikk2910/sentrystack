import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5001/api", // adjust to your actual backend port
  withCredentials: true, // sends the httpOnly refresh cookie automatically
});

// Holds the current access token in memory (set by AuthContext after login)
let accessToken = null;

export const setAccessToken = (token) => {
  accessToken = token;
};

// Attach the access token to every request
api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Handle 401s: try refreshing once, then retry the original request
let isRefreshing = false;
let queue = [];

const processQueue = (error, token = null) => {
  queue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve(token);
  });
  queue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // queue this request until the in-flight refresh finishes
        return new Promise((resolve, reject) => {
          queue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await axios.post(
          "http://localhost:5001/api/auth/refresh",
          {},
          { withCredentials: true },
        );
        setAccessToken(data.token);
        processQueue(null, data.token);
        originalRequest.headers.Authorization = `Bearer ${data.token}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        setAccessToken(null);
        // redirect to login — we'll wire this properly via AuthContext next step
        // window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  },
);

export default api;
