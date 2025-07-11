// WebAuthn関連の型定義

export interface WebAuthnCredential {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  attestation_type: string;
  transport: string[];
  flags: {
    user_present: boolean;
    user_verified: boolean;
    backup_eligible: boolean;
    backup_state: boolean;
  };
  sign_count: number;
  name: string;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
}

// 登録関連
export interface RegistrationStartRequest {
  user_id: string;
  username: string;
  display_name?: string;
}

export interface RegistrationStartResponse {
  session_id: string;
  expires_at: string;
  options: {
    challenge: string;
    rp: {
      name: string;
      id: string;
    };
    user: {
      id: string;
      name: string;
      displayName: string;
    };
    pubKeyCredParams: {
      type: 'public-key';
      alg: number;
    }[];
    timeout?: number;
    authenticatorSelection?: {
      authenticatorAttachment?: 'platform' | 'cross-platform';
      userVerification?: 'required' | 'preferred' | 'discouraged';
      requireResidentKey?: boolean;
    };
    attestation?: 'none' | 'indirect' | 'direct';
    excludeCredentials?: {
      type: 'public-key';
      id: string;
      transports?: string[];
    }[];
  };
}

export interface RegistrationFinishRequest {
  session_id: string;
  response: {
    id: string;
    rawId: string;
    type: 'public-key';
    response: {
      attestationObject: string;
      clientDataJSON: string;
    };
  };
  client_extensions?: Record<string, any>;
}

export interface RegistrationFinishResponse {
  success: boolean;
  credentialId: string;
  warnings?: string[];
  timestamp: number;
}

// 認証関連
export interface AuthenticationStartRequest {
  user_identifier?: string;
  user_verification?: 'required' | 'preferred' | 'discouraged';
}

export interface AuthenticationStartResponse {
  session_id: string;
  expires_at: string;
  options: {
    challenge: string;
    timeout?: number;
    rpId: string;
    userVerification?: 'required' | 'preferred' | 'discouraged';
    allowCredentials?: {
      type: 'public-key';
      id: string;
      transports?: string[];
    }[];
  };
}

export interface AuthenticationFinishRequest {
  session_id: string;
  response: {
    id: string;
    rawId: string;
    type: 'public-key';
    response: {
      authenticatorData: string;
      clientDataJSON: string;
      signature: string;
      userHandle?: string;
    };
  };
  client_extensions?: Record<string, any>;
}

export interface AuthenticationFinishResponse {
  success: boolean;
  user_id?: string;
  credential_id?: string;
  sign_count?: number;
  authentication_time?: string;
  warnings?: string[];
}

// ブラウザAPI関連
export interface PublicKeyCredentialCreationOptionsExtended extends PublicKeyCredentialCreationOptions {
  challenge: BufferSource;
  rp: {
    name: string;
    id?: string;
  };
  user: {
    id: BufferSource;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: {
    type: 'public-key';
    alg: number;
  }[];
  timeout?: number;
  excludeCredentials?: {
    type: 'public-key';
    id: BufferSource;
    transports?: AuthenticatorTransport[];
  }[];
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    userVerification?: 'required' | 'preferred' | 'discouraged';
    requireResidentKey?: boolean;
  };
  attestation?: 'none' | 'indirect' | 'direct';
}

export interface PublicKeyCredentialRequestOptionsExtended extends PublicKeyCredentialRequestOptions {
  challenge: BufferSource;
  timeout?: number;
  rpId?: string;
  allowCredentials?: {
    type: 'public-key';
    id: BufferSource;
    transports?: AuthenticatorTransport[];
  }[];
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

// エラー関連
export interface WebAuthnError {
  name: string;
  message: string;
  code?: string;
}

// 認証器管理関連
export interface CredentialsListResponse {
  credentials: WebAuthnCredential[];
}

export interface DeleteCredentialRequest {
  credential_id: string;
}

export interface UpdateCredentialRequest {
  credential_id: string;
  name: string;
}