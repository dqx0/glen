import React, { useState } from 'react';
import { 
  ChevronDownIcon, 
  ChevronRightIcon,
  ClipboardDocumentIcon,
  InformationCircleIcon,
  KeyIcon,
  CodeBracketIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  description: string;
  authentication: 'none' | 'required' | 'optional';
  requestBody?: any;
  responseBody?: any;
  parameters?: Array<{
    name: string;
    type: string;
    required: boolean;
    description: string;
  }>;
  scopes?: string[];
}

interface EndpointGroup {
  title: string;
  description: string;
  baseUrl: string;
  endpoints: Endpoint[];
}

const ApiDocumentation: React.FC = () => {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['auth']));
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set());

  const toggleGroup = (groupId: string) => {
    const newExpanded = new Set(expandedGroups);
    if (newExpanded.has(groupId)) {
      newExpanded.delete(groupId);
    } else {
      newExpanded.add(groupId);
    }
    setExpandedGroups(newExpanded);
  };

  const toggleEndpoint = (endpointId: string) => {
    const newExpanded = new Set(expandedEndpoints);
    if (newExpanded.has(endpointId)) {
      newExpanded.delete(endpointId);
    } else {
      newExpanded.add(endpointId);
    }
    setExpandedEndpoints(newExpanded);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const apiGroups: EndpointGroup[] = [
    {
      title: "OAuth2認証フロー",
      description: "標準的なOAuth2認証フローによるユーザー認証",
      baseUrl: "/api/v1/oauth2",
      endpoints: [
        {
          method: "GET",
          path: "/authorize",
          description: "OAuth2認証開始（認可コード取得）",
          authentication: "none",
          parameters: [
            {
              name: "client_id",
              type: "string",
              required: true,
              description: "OAuth2クライアントID"
            },
            {
              name: "redirect_uri",
              type: "string",
              required: true,
              description: "認可後のリダイレクトURL"
            },
            {
              name: "response_type",
              type: "string",
              required: true,
              description: "レスポンスタイプ（通常は 'code'）"
            },
            {
              name: "scope",
              type: "string",
              required: false,
              description: "要求するスコープ（space区切り）"
            },
            {
              name: "state",
              type: "string",
              required: false,
              description: "CSRF攻撃防止用のランダム文字列"
            }
          ],
          responseBody: "認可画面へのリダイレクト or 認可コード返却"
        },
        {
          method: "POST",
          path: "/token",
          description: "認可コードをアクセストークンに交換",
          authentication: "none",
          requestBody: {
            grant_type: "authorization_code",
            code: "認可コード",
            client_id: "OAuth2クライアントID",
            client_secret: "OAuth2クライアントシークレット",
            redirect_uri: "リダイレクトURL"
          },
          responseBody: {
            access_token: "アクセストークン",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "リフレッシュトークン",
            scope: "付与されたスコープ"
          }
        },
        {
          method: "POST",
          path: "/introspect",
          description: "トークンの有効性確認",
          authentication: "required",
          requestBody: {
            token: "検証対象のトークン",
            token_type_hint: "access_token | refresh_token"
          },
          responseBody: {
            active: true,
            client_id: "string",
            username: "string",
            scope: "string",
            exp: 1234567890
          },
          scopes: ["read"]
        }
      ]
    },
    {
      title: "WebAuthn認証連携",
      description: "⚠️ ブラウザ環境専用：パスキー・生体認証をWebアプリに統合。JavaScript Web APIが必要なため、サーバー間通信やcURLでは利用不可",
      baseUrl: "/api/v1/webauthn",
      endpoints: [
        {
          method: "POST",
          path: "/authenticate/start",
          description: "WebAuthn認証開始 - チャレンジ取得（ブラウザ環境でのみ有効）",
          authentication: "none",
          parameters: [
            {
              name: "user_identifier または user_id",
              type: "string",
              required: false,
              description: "指定時：そのユーザーの認証器のみ利用可能。未指定時：デバイス内のすべての認証器から選択可能（パスワードレス）"
            }
          ],
          requestBody: {
            user_identifier: "ユーザー名/メール（オプション）",
            user_id: "ユーザーID（オプション）"
          },
          responseBody: {
            session_id: "セッションID",
            options: {
              challenge: "チャレンジ文字列",
              timeout: 60000,
              rpId: "リライングパーティID",
              allowCredentials: "認証器情報（ユーザー指定時のみ）"
            },
            expires_at: "セッション有効期限"
          }
        },
        {
          method: "POST",
          path: "/authenticate/finish",
          description: "WebAuthn認証完了",
          authentication: "none",
          requestBody: {
            id: "認証器ID",
            rawId: "生の認証器ID",
            response: {
              authenticatorData: "認証器データ",
              clientDataJSON: "クライアントデータ",
              signature: "署名"
            },
            type: "public-key"
          },
          responseBody: {
            success: true,
            access_token: "JWTアクセストークン",
            user: {
              id: "ユーザーID",
              username: "ユーザー名"
            }
          }
        },
        {
          method: "POST",
          path: "/register/start",
          description: "WebAuthn登録開始",
          authentication: "required",
          requestBody: {
            username: "ユーザー名",
            display_name: "表示名"
          },
          responseBody: {
            rp: "リライングパーティ情報",
            user: "ユーザー情報",
            challenge: "チャレンジ文字列",
            pubKeyCredParams: "公開鍵パラメータ"
          },
          scopes: ["write"]
        },
        {
          method: "POST",
          path: "/register/finish",
          description: "WebAuthn登録完了",
          authentication: "required",
          requestBody: {
            id: "認証器ID",
            rawId: "生の認証器ID",
            response: {
              attestationObject: "アテステーションオブジェクト",
              clientDataJSON: "クライアントデータ"
            },
            type: "public-key"
          },
          responseBody: {
            success: true,
            credential_id: "認証器ID"
          },
          scopes: ["write"]
        }
      ]
    },
    {
      title: "ユーザー情報取得",
      description: "認証されたユーザーの基本情報を取得",
      baseUrl: "/api/v1/users",
      endpoints: [
        {
          method: "GET",
          path: "/{user_id}",
          description: "ユーザー詳細情報を取得",
          authentication: "required",
          parameters: [
            {
              name: "user_id",
              type: "string",
              required: true,
              description: "ユーザーID"
            }
          ],
          responseBody: {
            success: true,
            user: {
              id: "ユーザーID",
              username: "ユーザー名",
              email: "メールアドレス",
              email_verified: true,
              created_at: "作成日時",
              updated_at: "更新日時"
            }
          },
          scopes: ["read"]
        }
      ]
    }
  ];

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return '#10b981';
      case 'POST': return '#3b82f6';
      case 'PUT': return '#f59e0b';
      case 'DELETE': return '#ef4444';
      default: return '#6b7280';
    }
  };

  return (
    <div style={{ 
      maxWidth: '1200px', 
      margin: '0 auto', 
      padding: '2rem',
      backgroundColor: '#f9fafb',
      minHeight: '100vh'
    }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
          <CodeBracketIcon style={{ 
            width: '2rem', 
            height: '2rem', 
            color: 'var(--color-primary-600)',
            marginRight: '0.75rem'
          }} />
          <h1 style={{ 
            fontSize: '2rem', 
            fontWeight: 700, 
            color: '#1f2937',
            margin: 0
          }}>
            Glen ID API ドキュメント
          </h1>
        </div>
        <p style={{ 
          fontSize: '1.125rem', 
          color: '#6b7280',
          lineHeight: 1.6,
          margin: 0
        }}>
          外部開発者向けのGlen ID Platform API。APIキーを使用してあなたのアプリケーションに認証機能を統合できます。
        </p>
      </div>

      {/* API Base Information */}
      <div style={{
        backgroundColor: 'white',
        borderRadius: '0.5rem',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '1.5rem',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
          <InformationCircleIcon style={{ 
            width: '1.5rem', 
            height: '1.5rem', 
            color: 'var(--color-primary-600)',
            marginRight: '0.5rem'
          }} />
          <h2 style={{ 
            fontSize: '1.25rem', 
            fontWeight: 600, 
            color: '#1f2937',
            margin: 0
          }}>
            基本情報
          </h2>
        </div>

        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
          gap: '1.5rem' 
        }}>
          <div>
            <h3 style={{ 
              fontSize: '1rem', 
              fontWeight: 500, 
              color: '#374151',
              marginBottom: '0.5rem'
            }}>
              ベースURL
            </h3>
            <div style={{
              backgroundColor: '#f3f4f6',
              borderRadius: '0.375rem',
              padding: '0.75rem',
              fontFamily: 'monospace',
              fontSize: '0.875rem'
            }}>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>本番:</strong> https://api.glen.dqx0.com
              </div>
              <div>
                <strong>開発:</strong> http://localhost:8080
              </div>
            </div>
          </div>

          <div>
            <h3 style={{ 
              fontSize: '1rem', 
              fontWeight: 500, 
              color: '#374151',
              marginBottom: '0.5rem'
            }}>
              認証方法
            </h3>
            <div style={{
              backgroundColor: '#f3f4f6',
              borderRadius: '0.375rem',
              padding: '0.75rem',
              fontSize: '0.875rem'
            }}>
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center',
                  marginBottom: '0.25rem'
                }}>
                  <span style={{ fontWeight: 500, marginRight: '0.5rem' }}>1. OAuth2 (推奨):</span>
                </div>
                <code style={{ fontSize: '0.75rem', color: '#059669' }}>
                  Authorization: Bearer &lt;access_token&gt;
                </code>
              </div>
              <div>
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center',
                  marginBottom: '0.25rem'
                }}>
                  <KeyIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
                  <span style={{ fontWeight: 500, marginRight: '0.5rem' }}>2. APIキー:</span>
                  <button
                    onClick={() => copyToClipboard('Authorization: ApiKey glen_id_your_api_key_here')}
                    style={{
                      padding: '0.125rem',
                      border: 'none',
                      backgroundColor: 'transparent',
                      cursor: 'pointer'
                    }}
                  >
                    <ClipboardDocumentIcon style={{ width: '0.875rem', height: '0.875rem', color: '#6b7280' }} />
                  </button>
                </div>
                <code style={{ fontSize: '0.75rem', color: '#dc2626' }}>
                  Authorization: ApiKey glen_id_...
                </code>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.5rem' }}>
                ※ サーバーサイドアプリケーションでのみ使用
              </div>
            </div>
          </div>
        </div>

        <div style={{ 
          backgroundColor: '#fef3c7',
          border: '1px solid #f59e0b',
          borderRadius: '0.375rem',
          padding: '1rem',
          marginTop: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <ExclamationTriangleIcon style={{ 
              width: '1.25rem', 
              height: '1.25rem', 
              color: '#f59e0b',
              marginRight: '0.5rem'
            }} />
            <div>
              <p style={{ 
                fontSize: '0.875rem', 
                fontWeight: 500, 
                color: '#92400e',
                margin: '0 0 0.5rem 0'
              }}>
                重要：外部開発者向けAPI
              </p>
              <ul style={{ 
                fontSize: '0.75rem', 
                color: '#92400e',
                margin: 0,
                paddingLeft: '1rem',
                lineHeight: 1.4
              }}>
                <li>このAPIは外部アプリケーションからの統合用です</li>
                <li>OAuth2フローを推奨します（セキュアで標準的）</li>
                <li>APIキーはサーバーサイドでのみ使用してください</li>
                <li>クライアントサイドやフロントエンドに秘密情報を埋め込まないでください</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* API Groups */}
      {apiGroups.map((group, groupIndex) => {
        const groupId = group.title.toLowerCase().replace(/\s+/g, '-');
        const isGroupExpanded = expandedGroups.has(groupId);

        return (
          <div
            key={groupIndex}
            style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
              marginBottom: '1.5rem',
              overflow: 'hidden'
            }}
          >
            {/* Group Header */}
            <button
              onClick={() => toggleGroup(groupId)}
              style={{
                width: '100%',
                padding: '1.5rem',
                border: 'none',
                backgroundColor: 'transparent',
                textAlign: 'left',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}
            >
              <div>
                <h2 style={{ 
                  fontSize: '1.25rem', 
                  fontWeight: 600, 
                  color: '#1f2937',
                  margin: '0 0 0.5rem 0'
                }}>
                  {group.title}
                </h2>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#6b7280',
                  margin: 0
                }}>
                  {group.description}
                </p>
                <code style={{
                  fontSize: '0.75rem',
                  color: 'var(--color-primary-600)',
                  backgroundColor: '#f0f9ff',
                  padding: '0.25rem 0.5rem',
                  borderRadius: '0.25rem',
                  marginTop: '0.5rem',
                  display: 'inline-block'
                }}>
                  {group.baseUrl}
                </code>
              </div>
              {isGroupExpanded ? (
                <ChevronDownIcon style={{ width: '1.5rem', height: '1.5rem', color: '#6b7280' }} />
              ) : (
                <ChevronRightIcon style={{ width: '1.5rem', height: '1.5rem', color: '#6b7280' }} />
              )}
            </button>

            {/* Group Content */}
            {isGroupExpanded && (
              <div style={{ borderTop: '1px solid #e5e7eb' }}>
                {group.endpoints.map((endpoint, endpointIndex) => {
                  const endpointId = `${groupId}-${endpointIndex}`;
                  const isEndpointExpanded = expandedEndpoints.has(endpointId);

                  return (
                    <div key={endpointIndex} style={{ borderBottom: '1px solid #f3f4f6' }}>
                      {/* Endpoint Header */}
                      <button
                        onClick={() => toggleEndpoint(endpointId)}
                        style={{
                          width: '100%',
                          padding: '1rem 1.5rem',
                          border: 'none',
                          backgroundColor: 'transparent',
                          textAlign: 'left',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                          <span style={{
                            display: 'inline-block',
                            padding: '0.25rem 0.75rem',
                            borderRadius: '0.375rem',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            color: 'white',
                            backgroundColor: getMethodColor(endpoint.method),
                            minWidth: '4rem',
                            textAlign: 'center'
                          }}>
                            {endpoint.method}
                          </span>
                          <div>
                            <code style={{
                              fontSize: '0.875rem',
                              fontWeight: 500,
                              color: '#1f2937'
                            }}>
                              {group.baseUrl}{endpoint.path}
                            </code>
                            <p style={{
                              fontSize: '0.75rem',
                              color: '#6b7280',
                              margin: '0.25rem 0 0 0'
                            }}>
                              {endpoint.description}
                            </p>
                          </div>
                        </div>
                        {isEndpointExpanded ? (
                          <ChevronDownIcon style={{ width: '1.25rem', height: '1.25rem', color: '#6b7280' }} />
                        ) : (
                          <ChevronRightIcon style={{ width: '1.25rem', height: '1.25rem', color: '#6b7280' }} />
                        )}
                      </button>

                      {/* Endpoint Details */}
                      {isEndpointExpanded && (
                        <div style={{ 
                          padding: '0 1.5rem 1.5rem',
                          backgroundColor: '#f9fafb'
                        }}>
                          {/* Authentication & Scopes */}
                          <div style={{ 
                            display: 'flex', 
                            gap: '1rem',
                            marginBottom: '1rem',
                            flexWrap: 'wrap'
                          }}>
                            <div>
                              <span style={{
                                fontSize: '0.75rem',
                                fontWeight: 500,
                                color: '#374151'
                              }}>
                                認証:
                              </span>
                              <span style={{
                                marginLeft: '0.5rem',
                                padding: '0.125rem 0.5rem',
                                borderRadius: '9999px',
                                fontSize: '0.625rem',
                                fontWeight: 500,
                                backgroundColor: endpoint.authentication === 'required' ? '#fef2f2' : '#f0fdf4',
                                color: endpoint.authentication === 'required' ? '#b91c1c' : '#16a34a'
                              }}>
                                {endpoint.authentication === 'required' ? '必須' : '不要'}
                              </span>
                            </div>
                            {endpoint.scopes && (
                              <div>
                                <span style={{
                                  fontSize: '0.75rem',
                                  fontWeight: 500,
                                  color: '#374151'
                                }}>
                                  必要なスコープ:
                                </span>
                                {endpoint.scopes.map((scope, i) => (
                                  <span
                                    key={i}
                                    style={{
                                      marginLeft: '0.5rem',
                                      padding: '0.125rem 0.5rem',
                                      borderRadius: '9999px',
                                      fontSize: '0.625rem',
                                      fontWeight: 500,
                                      backgroundColor: '#e0e7ff',
                                      color: '#3730a3'
                                    }}
                                  >
                                    {scope}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* Parameters */}
                          {endpoint.parameters && endpoint.parameters.length > 0 && (
                            <div style={{ marginBottom: '1rem' }}>
                              <h4 style={{
                                fontSize: '0.875rem',
                                fontWeight: 500,
                                color: '#1f2937',
                                marginBottom: '0.5rem'
                              }}>
                                パラメータ
                              </h4>
                              <div style={{
                                backgroundColor: 'white',
                                borderRadius: '0.375rem',
                                border: '1px solid #e5e7eb',
                                overflow: 'hidden'
                              }}>
                                {endpoint.parameters.map((param, i) => (
                                  <div
                                    key={i}
                                    style={{
                                      padding: '0.75rem',
                                      borderBottom: i < endpoint.parameters!.length - 1 ? '1px solid #f3f4f6' : 'none'
                                    }}
                                  >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                      <code style={{ fontSize: '0.75rem', fontWeight: 500 }}>
                                        {param.name}
                                      </code>
                                      <span style={{
                                        fontSize: '0.625rem',
                                        color: '#6b7280',
                                        backgroundColor: '#f3f4f6',
                                        padding: '0.125rem 0.375rem',
                                        borderRadius: '0.25rem'
                                      }}>
                                        {param.type}
                                      </span>
                                      {param.required && (
                                        <span style={{
                                          fontSize: '0.625rem',
                                          color: '#dc2626',
                                          backgroundColor: '#fef2f2',
                                          padding: '0.125rem 0.375rem',
                                          borderRadius: '0.25rem'
                                        }}>
                                          必須
                                        </span>
                                      )}
                                    </div>
                                    <p style={{
                                      fontSize: '0.75rem',
                                      color: '#6b7280',
                                      margin: '0.25rem 0 0 0'
                                    }}>
                                      {param.description}
                                    </p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Request Body */}
                          {endpoint.requestBody && (
                            <div style={{ marginBottom: '1rem' }}>
                              <h4 style={{
                                fontSize: '0.875rem',
                                fontWeight: 500,
                                color: '#1f2937',
                                marginBottom: '0.5rem'
                              }}>
                                リクエストボディ
                              </h4>
                              <div style={{
                                backgroundColor: '#1f2937',
                                borderRadius: '0.375rem',
                                padding: '1rem',
                                overflow: 'auto'
                              }}>
                                <pre style={{
                                  color: '#f9fafb',
                                  fontSize: '0.75rem',
                                  margin: 0,
                                  fontFamily: 'monospace'
                                }}>
                                  {JSON.stringify(endpoint.requestBody, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}

                          {/* Response Body */}
                          {endpoint.responseBody && (
                            <div style={{ marginBottom: '1rem' }}>
                              <h4 style={{
                                fontSize: '0.875rem',
                                fontWeight: 500,
                                color: '#1f2937',
                                marginBottom: '0.5rem'
                              }}>
                                レスポンス例
                              </h4>
                              <div style={{
                                backgroundColor: '#1f2937',
                                borderRadius: '0.375rem',
                                padding: '1rem',
                                overflow: 'auto'
                              }}>
                                <pre style={{
                                  color: '#f9fafb',
                                  fontSize: '0.75rem',
                                  margin: 0,
                                  fontFamily: 'monospace'
                                }}>
                                  {JSON.stringify(endpoint.responseBody, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}

                          {/* Implementation Example */}
                          <div>
                            <h4 style={{
                              fontSize: '0.875rem',
                              fontWeight: 500,
                              color: '#1f2937',
                              marginBottom: '0.5rem'
                            }}>
                              {group.baseUrl.includes('webauthn') ? 'JavaScript実装例（ブラウザ専用）' : 'cURL例'}
                            </h4>
                            <div style={{
                              backgroundColor: '#1f2937',
                              borderRadius: '0.375rem',
                              padding: '1rem',
                              position: 'relative'
                            }}>
                              <button
                                onClick={() => {
                                  const example = group.baseUrl.includes('webauthn') ? 
                                    `// WebAuthn認証の実装例
const startAuth = async () => {
  // 1. チャレンジ取得
  const response = await fetch('/api/v1/webauthn/authenticate/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_identifier: 'user@example.com' })
  });
  const { options } = await response.json();

  // 2. ブラウザの認証器API呼び出し
  const credential = await navigator.credentials.get({
    publicKey: options
  });

  // 3. 認証完了
  const finishResponse = await fetch('/api/v1/webauthn/authenticate/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential: credential,
      session_id: sessionId
    })
  });
};` :
                                    `curl -X ${endpoint.method} "https://api.glen.dqx0.com${group.baseUrl}${endpoint.path}" \\
  -H "Authorization: ApiKey your_api_key_here" \\
  -H "Content-Type: application/json"${endpoint.requestBody ? ` \\
  -d '${JSON.stringify(endpoint.requestBody)}'` : ''}`;
                                  copyToClipboard(example);
                                }}
                                style={{
                                  position: 'absolute',
                                  top: '0.5rem',
                                  right: '0.5rem',
                                  padding: '0.25rem',
                                  border: 'none',
                                  backgroundColor: 'transparent',
                                  cursor: 'pointer'
                                }}
                              >
                                <ClipboardDocumentIcon style={{ width: '1rem', height: '1rem', color: '#9ca3af' }} />
                              </button>
                              <pre style={{
                                color: '#f9fafb',
                                fontSize: '0.75rem',
                                margin: 0,
                                fontFamily: 'monospace',
                                overflow: 'auto'
                              }}>
{group.baseUrl.includes('webauthn') ? 
`// WebAuthn認証の実装例
const startAuth = async () => {
  // 1. チャレンジ取得
  const response = await fetch('/api/v1/webauthn/authenticate/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_identifier: 'user@example.com' })
  });
  const { options } = await response.json();

  // 2. ブラウザの認証器API呼び出し
  const credential = await navigator.credentials.get({
    publicKey: options
  });

  // 3. 認証完了
  const finishResponse = await fetch('/api/v1/webauthn/authenticate/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential: credential,
      session_id: sessionId
    })
  });
};` :
`curl -X ${endpoint.method} "https://api.glen.dqx0.com${group.baseUrl}${endpoint.path}" \\
  -H "Authorization: ApiKey your_api_key_here" \\
  -H "Content-Type: application/json"${endpoint.requestBody ? ` \\
  -d '${JSON.stringify(endpoint.requestBody)}'` : ''}`}
                              </pre>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {/* Footer */}
      <div style={{
        backgroundColor: 'white',
        borderRadius: '0.5rem',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '1.5rem',
        textAlign: 'center'
      }}>
        <p style={{
          fontSize: '0.875rem',
          color: '#6b7280',
          margin: 0
        }}>
          ご質問やサポートが必要な場合は、開発チームまでお問い合わせください。
        </p>
      </div>
    </div>
  );
};

export default ApiDocumentation;