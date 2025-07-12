import apiClient from '../api/client';
import type {
  RegistrationStartRequest,
  RegistrationStartResponse,
  RegistrationFinishRequest,
  RegistrationFinishResponse,
  AuthenticationStartRequest,
  AuthenticationStartResponse,
  AuthenticationFinishRequest,
  AuthenticationFinishResponse,
  CredentialsListResponse,
  DeleteCredentialRequest,
  UpdateCredentialRequest,
  WebAuthnCredential,
  WebAuthnError,
  PublicKeyCredentialCreationOptionsExtended,
  PublicKeyCredentialRequestOptionsExtended,
} from '../types/webauthn';

export class WebAuthnService {
  private static readonly WEBAUTHN_BASE_URL = '/api/v1/webauthn';

  // WebAuthn サポートチェック
  static isSupported(): boolean {
    return !!(typeof navigator !== 'undefined' && 
             navigator.credentials && 
             typeof navigator.credentials.create === 'function' && 
             typeof navigator.credentials.get === 'function' &&
             typeof window !== 'undefined' && 
             'PublicKeyCredential' in window);
  }

  // プラットフォーム認証器サポートチェック（Touch ID、Face ID、Windows Hello等）
  static async isPlatformAuthenticatorSupported(): Promise<boolean> {
    if (!this.isSupported()) return false;
    
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  // === 登録フロー ===

  // 登録開始 - チャレンジとオプションを取得
  static async startRegistration(request: RegistrationStartRequest): Promise<RegistrationStartResponse> {
    const response = await apiClient.post<RegistrationStartResponse>(
      `${this.WEBAUTHN_BASE_URL}/register/start`,
      request
    );
    return response.data;
  }

  // 登録完了 - 認証器からの応答を検証
  static async finishRegistration(request: RegistrationFinishRequest): Promise<RegistrationFinishResponse> {
    const response = await apiClient.post<RegistrationFinishResponse>(
      `${this.WEBAUTHN_BASE_URL}/register/finish`,
      request
    );
    return response.data;
  }

  // WebAuthn認証器登録フロー実行
  static async registerCredential(
    userId: string,
    username: string,
    credentialName: string,
    displayName?: string
  ): Promise<WebAuthnCredential> {
    if (!this.isSupported()) {
      throw new Error('WebAuthnはこのブラウザでサポートされていません');
    }

    try {
      // 1. 登録開始 - サーバーからチャレンジとオプションを取得
      const startResponse = await this.startRegistration({
        user_id: userId,
        username,
        display_name: displayName,
      });

      // 2. ブラウザAPIで認証器に登録オプションを変換
      const options = this.convertRegistrationOptions(startResponse);

      // 3. 認証器で新しい認証情報を作成
      const credential = await navigator.credentials.create({
        publicKey: options,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('認証器からの応答がありません');
      }

      // 4. 認証器からの応答をサーバーに送信して検証
      const finishResponse = await this.finishRegistration({
        session_id: startResponse.session_id,
        response: this.serializeCredentialForRegistration(credential),
        credential_name: credentialName,
      });

      if (!finishResponse.success) {
        throw new Error('認証器の検証に失敗しました');
      }

      // Return a simplified credential object since server doesn't return full credential
      return {
        id: finishResponse.credentialId,
        user_id: userId,
        credential_id: finishResponse.credentialId,
        public_key: '',
        attestation_type: 'none',
        transport: [],
        flags: {
          user_present: true,
          user_verified: false,
          backup_eligible: false,
          backup_state: false,
        },
        sign_count: 0,
        name: credentialName,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

    } catch (error: unknown) {
      console.error('WebAuthn registration failed:', error);
      throw this.handleWebAuthnError(error);
    }
  }

  // === 認証フロー ===

  // 認証開始 - チャレンジとオプションを取得
  static async startAuthentication(request: AuthenticationStartRequest): Promise<AuthenticationStartResponse> {
    const response = await apiClient.post<AuthenticationStartResponse>(
      `${this.WEBAUTHN_BASE_URL}/authenticate/start`,
      request
    );
    return response.data;
  }

  // 認証完了 - 認証器からの応答を検証
  static async finishAuthentication(request: AuthenticationFinishRequest): Promise<AuthenticationFinishResponse> {
    const response = await apiClient.post<AuthenticationFinishResponse>(
      `${this.WEBAUTHN_BASE_URL}/authenticate/finish`,
      request
    );
    return response.data;
  }

  // WebAuthn認証フロー実行
  static async authenticateCredential(username: string): Promise<AuthenticationFinishResponse> {
    if (!this.isSupported()) {
      throw new Error('WebAuthnはこのブラウザでサポートされていません');
    }

    try {
      // 1. 認証開始 - サーバーからチャレンジとオプションを取得
      const startResponse = await this.startAuthentication({
        user_identifier: username,
        user_verification: 'preferred',
      });

      // 2. ブラウザAPIで認証オプションを変換
      const options = this.convertAuthenticationOptions(startResponse);

      // 3. 認証器で認証を実行
      const credential = await navigator.credentials.get({
        publicKey: options,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('認証器からの応答がありません');
      }

      // 4. 認証器からの応答をサーバーに送信して検証
      const finishResponse = await this.finishAuthentication({
        session_id: startResponse.session_id,
        response: this.serializeCredentialForAuthentication(credential),
      });

      if (!finishResponse.success) {
        throw new Error('認証に失敗しました');
      }

      return finishResponse;

    } catch (error: unknown) {
      console.error('WebAuthn authentication failed:', error);
      throw this.handleWebAuthnError(error);
    }
  }

  // === 認証器管理 ===

  // ユーザーの認証器一覧を取得
  static async getCredentials(): Promise<CredentialsListResponse> {
    const response = await apiClient.get<CredentialsListResponse>(
      `${this.WEBAUTHN_BASE_URL}/credentials`
    );
    return response.data;
  }

  // 認証器を削除
  static async deleteCredential(request: DeleteCredentialRequest): Promise<void> {
    await apiClient.delete(`${this.WEBAUTHN_BASE_URL}/credentials/${request.credential_id}`);
  }

  // 認証器名を更新
  static async updateCredential(request: UpdateCredentialRequest): Promise<WebAuthnCredential> {
    const response = await apiClient.put<WebAuthnCredential>(
      `${this.WEBAUTHN_BASE_URL}/credentials/${request.credential_id}`,
      { name: request.name }
    );
    return response.data;
  }

  // === ユーティリティメソッド ===

  // サーバーレスポンスをブラウザAPI用のオプションに変換（登録）
  private static convertRegistrationOptions(
    serverOptions: RegistrationStartResponse
  ): PublicKeyCredentialCreationOptionsExtended {
    const options = serverOptions.options;
    if (!options) {
      throw new Error('Server response missing options field');
    }
    
    return {
      challenge: this.base64ToBuffer(options.challenge),
      rp: options.rp,
      user: {
        id: this.base64ToBuffer(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout,
      excludeCredentials: options.excludeCredentials?.map(cred => ({
        type: cred.type,
        id: this.base64ToBuffer(cred.id),
        transports: cred.transports as AuthenticatorTransport[],
      })),
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
    };
  }

  // サーバーレスポンスをブラウザAPI用のオプションに変換（認証）
  private static convertAuthenticationOptions(
    serverOptions: AuthenticationStartResponse
  ): PublicKeyCredentialRequestOptionsExtended {
    const options = serverOptions.options;
    if (!options) {
      throw new Error('Server response missing options field');
    }
    
    return {
      challenge: this.base64ToBuffer(options.challenge),
      timeout: options.timeout,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(cred => ({
        type: cred.type,
        id: this.base64ToBuffer(cred.id),
        transports: cred.transports as AuthenticatorTransport[],
      })),
      userVerification: options.userVerification,
    };
  }

  // 認証器からのレスポンスをサーバー送信用にシリアライズ（登録）
  private static serializeCredentialForRegistration(credential: PublicKeyCredential) {
    const response = credential.response as AuthenticatorAttestationResponse;
    
    return {
      id: credential.id,
      rawId: this.bufferToBase64(credential.rawId),
      type: credential.type as 'public-key',
      response: {
        attestationObject: this.bufferToBase64(response.attestationObject),
        clientDataJSON: this.bufferToBase64(response.clientDataJSON),
      },
    };
  }

  // 認証器からのレスポンスをサーバー送信用にシリアライズ（認証）
  private static serializeCredentialForAuthentication(credential: PublicKeyCredential) {
    const response = credential.response as AuthenticatorAssertionResponse;
    
    return {
      id: credential.id,
      rawId: this.bufferToBase64(credential.rawId),
      type: credential.type as 'public-key',
      response: {
        authenticatorData: this.bufferToBase64(response.authenticatorData),
        clientDataJSON: this.bufferToBase64(response.clientDataJSON),
        signature: this.bufferToBase64(response.signature),
        userHandle: response.userHandle ? this.bufferToBase64(response.userHandle) : undefined,
      },
    };
  }

  // Base64文字列をArrayBufferに変換
  private static base64ToBuffer(base64: string): ArrayBuffer {
    if (!base64 || typeof base64 !== 'string') {
      throw new Error('Invalid base64 string: value is undefined, null, or not a string');
    }
    
    // URL-safe base64 decode
    const base64Url = base64.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64Padded = base64Url + padding;
    
    const binary = atob(base64Padded);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }
    
    return buffer;
  }

  // ArrayBufferをBase64文字列に変換
  private static bufferToBase64(buffer: ArrayBuffer): string {
    const view = new Uint8Array(buffer);
    let binary = '';
    
    for (let i = 0; i < view.byteLength; i++) {
      binary += String.fromCharCode(view[i]);
    }
    
    // URL-safe base64 encode
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // WebAuthnエラーを適切なエラーメッセージに変換
  private static handleWebAuthnError(error: unknown): Error {
    const err = error as any;
    const webauthnError: WebAuthnError = {
      name: err?.name || 'UnknownError',
      message: err?.message || 'WebAuthn操作が失敗しました',
      code: err?.code,
    };

    switch (webauthnError.name) {
      case 'NotSupportedError':
        return new Error('お使いのブラウザはWebAuthnをサポートしていません');
      case 'SecurityError':
        return new Error('セキュリティエラーが発生しました。HTTPSまたはlocalhostでアクセスしてください');
      case 'NotAllowedError':
        return new Error('ユーザーによって操作がキャンセルされました');
      case 'InvalidStateError':
        return new Error('認証器は既に登録されています');
      case 'ConstraintError':
        return new Error('認証器の制約により操作を完了できませんでした');
      case 'AbortError':
        return new Error('操作がタイムアウトまたは中断されました');
      default:
        return new Error(webauthnError.message);
    }
  }

  // 認証器の種類を判定
  static getAuthenticatorType(credential: WebAuthnCredential): string {
    // transport が存在しない場合のフォールバック
    const transport = credential.transport || [];
    const transportArray = Array.isArray(transport) ? transport : [transport];
    
    if (transportArray.includes('internal')) {
      return 'プラットフォーム認証器';
    } else if (transportArray.some(t => ['usb', 'nfc', 'ble'].includes(t))) {
      return 'ローミング認証器';
    }
    return '不明';
  }

  // 認証器のアイコンを取得
  static getAuthenticatorIcon(credential: WebAuthnCredential): string {
    // transport が存在しない場合のフォールバック
    const transport = credential.transport || [];
    const transportArray = Array.isArray(transport) ? transport : [transport];
    
    if (transportArray.includes('internal')) {
      return '📱'; // プラットフォーム認証器（Touch ID、Face ID等）
    } else if (transportArray.includes('usb')) {
      return '🔑'; // USBセキュリティキー
    } else if (transportArray.includes('nfc')) {
      return '📡'; // NFC
    } else if (transportArray.includes('ble')) {
      return '📶'; // Bluetooth
    }
    return '🔐'; // 汎用
  }
}