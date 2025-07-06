import apiClient from '../api/client';
import type {
  RegisterRequest,
  RegisterResponse,
  LoginRequest as UserLoginRequest,
  LoginResponse as UserLoginResponse,
  User,
} from '../types/user';

export class UserService {
  private static readonly USER_BASE_URL = '/api/v1/users';

  // ユーザー登録
  static async register(request: RegisterRequest): Promise<RegisterResponse> {
    const response = await apiClient.post<RegisterResponse>(
      `${this.USER_BASE_URL}/register`,
      request
    );
    return response.data;
  }

  // ユーザーログイン
  static async login(request: UserLoginRequest): Promise<UserLoginResponse> {
    const response = await apiClient.post<UserLoginResponse>(
      `${this.USER_BASE_URL}/login`,
      request
    );
    return response.data;
  }

  // ユーザー情報取得
  static async getUser(): Promise<User> {
    const response = await apiClient.get<User>(`${this.USER_BASE_URL}`);
    return response.data;
  }

  // ローカルストレージからユーザー情報を取得
  static getStoredUser(): User | null {
    const userStr = localStorage.getItem('user');
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch (error) {
      console.error('Failed to parse stored user:', error);
      return null;
    }
  }

  // ローカルストレージにユーザー情報を保存
  static storeUser(user: User): void {
    localStorage.setItem('user', JSON.stringify(user));
  }

  // ローカルストレージからユーザー情報を削除
  static clearUser(): void {
    localStorage.removeItem('user');
  }
}