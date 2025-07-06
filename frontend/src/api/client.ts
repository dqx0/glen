import axios from 'axios';

// API Base URL - 環境変数から取得、デフォルトはlocalhost
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// Axiosインスタンスを作成
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// リクエストインターセプター（認証トークンの自動付与）
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// レスポンスインターセプター（エラーハンドリング）
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // 401エラーの場合、トークンをクリアして再ログインを促す
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      // ログインページにリダイレクト
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default apiClient;
