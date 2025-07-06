// ソーシャルログイン関連の型定義

export type SocialProvider = 'google' | 'github' | 'discord';

export interface SocialAccount {
  id: string;
  user_id: string;
  provider: SocialProvider;
  provider_id: string;
  email?: string;
  name?: string;
  avatar_url?: string;
  created_at: string;
  updated_at: string;
}

export interface AuthorizeRequest {
  provider: SocialProvider;
  redirect_uri: string;
  state?: string;
}

export interface AuthorizeResponse {
  authorization_url: string;
  state: string;
}

export interface CallbackRequest {
  provider: SocialProvider;
  code: string;
  state: string;
  redirect_uri: string;
}

export interface CallbackResponse {
  user: {
    id: string;
    username: string;
    email: string;
    created_at: string;
    updated_at: string;
  };
  social_account: SocialAccount;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  scopes: string[];
}

export interface ProvidersResponse {
  providers: {
    provider: SocialProvider;
    name: string;
    enabled: boolean;
    scopes: string[];
  }[];
}

export interface SocialAccountsResponse {
  accounts: SocialAccount[];
}

export interface UnlinkAccountRequest {
  account_id: string;
}