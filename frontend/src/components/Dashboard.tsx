import {
  ArrowRightOnRectangleIcon,
  ClockIcon,
  KeyIcon,
  PlusIcon,
  TagIcon,
  TrashIcon,
  UserIcon,
  XMarkIcon,
  ShieldCheckIcon,
  ChartBarIcon,
  GlobeAltIcon,
  CpuChipIcon,
  LightBulbIcon,
  SparklesIcon,
  BoltIcon,
  EyeIcon,
  CubeIcon,
  RocketLaunchIcon
} from '@heroicons/react/24/outline';
import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { AuthService } from '../services/authService';
import type { Token } from '../types/auth';
import { getErrorMessage } from '../utils/errorUtils';
import ApiDocumentation from './ApiDocumentation';
import OAuth2ClientsSection from './OAuth2ClientsSection';
import SocialAccountsSection from './SocialAccountsSection';
import WebAuthnCredentialsSection from './WebAuthnCredentialsSection';

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creatingApiKey, setCreatingApiKey] = useState(false);
  const [apiKeyName, setApiKeyName] = useState('');
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [socialLinkedKey, setSocialLinkedKey] = useState(0);
  const [authTab, setAuthTab] = useState<'overview' | 'oauth2' | 'apikeys' | 'docs'>('overview');
  const [windowWidth, setWindowWidth] = useState(typeof window !== 'undefined' ? window.innerWidth : 1024);
  const [statsVisible, setStatsVisible] = useState(false);
  const [animateCards, setAnimateCards] = useState(false);

  useEffect(() => {
    const handleResize = () => setWindowWidth(window.innerWidth);
    window.addEventListener('resize', handleResize);
    
    // Animation triggers
    const timer1 = setTimeout(() => setStatsVisible(true), 300);
    const timer2 = setTimeout(() => setAnimateCards(true), 600);
    
    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, []);

  useEffect(() => {
    console.log('Dashboard - useEffect, user:', user);
    if (user) {
      loadTokens();
    }
  }, [user]);

  useEffect(() => {
    // ソーシャルアカウント連携後のリフレッシュ
    const params = new URLSearchParams(location.search);
    if (params.get('social_linked') === 'true') {
      console.log('Social account linked, refreshing data');
      setSocialLinkedKey(prev => prev + 1);
      // URLパラメータをクリア
      window.history.replaceState({}, '', '/dashboard');
    }
  }, [location]);

  const loadTokens = async () => {
    if (!user || !user.id) {
      console.log('Dashboard - loadTokens: user or user.id is missing', { user });
      return;
    }

    try {
      setLoading(true);
      setError(null);
      console.log('Dashboard - loadTokens: calling AuthService.listTokens with user.id:', user.id);
      const userTokens = await AuthService.listTokens(user.id);

      // 安全な配列アクセス
      const safeTokens = Array.isArray(userTokens) ? userTokens : [];
      setTokens(safeTokens);
    } catch (error: unknown) {
      console.error('Failed to load tokens:', error);
      setError(getErrorMessage(error, 'トークンの読み込みに失敗しました'));
      // エラー時のフォールバック
      setTokens([]);
    } finally {
      setLoading(false);
    }
  };

  const createApiKey = async () => {
    if (!user || !user.id || !apiKeyName.trim()) return;

    try {
      setCreatingApiKey(true);
      const response = await AuthService.createAPIKey({
        user_id: user.id,
        name: apiKeyName.trim(),
        scopes: ['read', 'write'],
      });

      setNewApiKey(response.api_key);
      setApiKeyName('');
      await loadTokens();
    } catch (error: unknown) {
      console.error('Failed to create API key:', error);
      setError(getErrorMessage(error, 'APIキーの作成に失敗しました'));
    } finally {
      setCreatingApiKey(false);
    }
  };

  const revokeToken = async (tokenId: string) => {
    if (!user || !user.id) return;

    try {
      await AuthService.revokeToken({
        token_id: tokenId,
        user_id: user.id,
      });
      await loadTokens();
    } catch (error: unknown) {
      console.error('Failed to revoke token:', error);
      setError(getErrorMessage(error, 'トークンの無効化に失敗しました'));
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('ja-JP');
  };

  const closeApiKeyModal = () => {
    setNewApiKey(null);
  };

  // Mock statistics data for modern dashboard
  const stats = [
    { label: 'アクティブセッション', value: '1', icon: EyeIcon, color: 'from-blue-500 to-cyan-500' },
    { label: 'WebAuthn認証器', value: '2', icon: ShieldCheckIcon, color: 'from-green-500 to-emerald-500' },
    { label: 'APIコール (30日)', value: '1,247', icon: ChartBarIcon, color: 'from-purple-500 to-pink-500' },
    { label: 'セキュリティスコア', value: '98%', icon: CpuChipIcon, color: 'from-orange-500 to-red-500' }
  ];

  const techFeatures = [
    { 
      title: 'WebAuthn FIDO2', 
      description: 'パスワードレス生体認証', 
      icon: ShieldCheckIcon, 
      color: 'text-blue-500',
      bg: 'bg-blue-50',
      detail: 'Touch ID・Face ID・Windows Hello対応'
    },
    { 
      title: 'OAuth2 統合', 
      description: 'Google・GitHub・Discord', 
      icon: GlobeAltIcon, 
      color: 'text-green-500',
      bg: 'bg-green-50',
      detail: 'マルチプロバイダー認証'
    },
    { 
      title: 'JWT セキュア', 
      description: 'ステートレス認証', 
      icon: CubeIcon, 
      color: 'text-purple-500',
      bg: 'bg-purple-50',
      detail: 'RS256・リフレッシュトークン'
    },
    { 
      title: 'API管理', 
      description: 'スコープベース制御', 
      icon: CpuChipIcon, 
      color: 'text-orange-500',
      bg: 'bg-orange-50',
      detail: 'RESTful・OpenAPI準拠'
    }
  ];

  if (!user) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div style={{ fontSize: '1.125rem', color: '#6b7280' }}>
          ユーザー情報を読み込んでいます...
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
        {/* Modern Header with Glassmorphism */}
        <header className="backdrop-blur-xl bg-white/80 border-b border-white/20 shadow-lg sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center space-x-4">
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full blur opacity-75 animate-pulse"></div>
                  <RocketLaunchIcon className="relative w-8 h-8 text-blue-600" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    Glen ID Platform
                  </h1>
                  <p className="text-sm text-gray-500">WebAuthn-First Authentication</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-4">
                <div className="hidden md:flex items-center space-x-2 px-3 py-1 bg-green-100 rounded-full">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-sm font-medium text-green-700">オンライン</span>
                </div>
                <button
                  onClick={logout}
                  className="flex items-center px-4 py-2 bg-gradient-to-r from-gray-100 to-gray-200 hover:from-gray-200 hover:to-gray-300 rounded-xl transition-all duration-300 transform hover:scale-105"
                >
                  <ArrowRightOnRectangleIcon className="w-4 h-4 mr-2" />
                  <span className="font-medium">ログアウト</span>
                </button>
              </div>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Hero Stats Section */}
          <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8 transition-all duration-1000 ${statsVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
            {stats.map((stat, index) => (
              <div 
                key={stat.label}
                className={`relative p-6 bg-white/70 backdrop-blur-sm rounded-2xl shadow-lg border border-white/20 hover:shadow-xl transition-all duration-500 transform hover:-translate-y-2 ${animateCards ? 'animate-bounce' : ''}`}
                style={{ animationDelay: `${index * 0.1}s`, animationDuration: '0.6s', animationFillMode: 'both' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600 mb-1">{stat.label}</p>
                    <p className="text-3xl font-bold text-gray-900">{stat.value}</p>
                  </div>
                  <div className={`p-3 rounded-xl bg-gradient-to-br ${stat.color}`}>
                    <stat.icon className="w-6 h-6 text-white" />
                  </div>
                </div>
                <div className={`absolute inset-0 bg-gradient-to-br ${stat.color} opacity-0 hover:opacity-10 rounded-2xl transition-opacity duration-300`}></div>
              </div>
            ))}
          </div>

          {/* Tech Features Showcase */}
          <div className="mb-8">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-4">
                最先端技術スタック
              </h2>
              <p className="text-gray-600 max-w-2xl mx-auto">
                WebAuthn FIDO2、OAuth2、JWT、マイクロサービスアーキテクチャによる次世代認証プラットフォーム
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {techFeatures.map((feature, index) => (
                <div 
                  key={feature.title}
                  className="group relative p-6 bg-white/80 backdrop-blur-sm rounded-2xl shadow-lg border border-white/20 hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-3 hover:rotate-1"
                >
                  <div className={`p-3 ${feature.bg} rounded-xl mb-4 w-fit group-hover:scale-110 transition-transform duration-300`}>
                    <feature.icon className={`w-8 h-8 ${feature.color}`} />
                  </div>
                  <h3 className="text-xl font-bold text-gray-900 mb-2">{feature.title}</h3>
                  <p className="text-gray-600 mb-3">{feature.description}</p>
                  <p className="text-sm text-gray-500">{feature.detail}</p>
                  
                  {/* Hover effect overlay */}
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  
                  {/* Animated border */}
                  <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-blue-500 to-purple-500 animate-pulse" style={{padding: '1px'}}>
                      <div className="w-full h-full bg-white rounded-2xl"></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-8">

            {/* User Info & Social Accounts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* User Info Card */}
              <div className="lg:col-span-1">
                <div className="relative p-6 bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 overflow-hidden group hover:shadow-2xl transition-all duration-500">
                  {/* Animated background */}
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-50/50 to-indigo-50/50 group-hover:from-blue-100/50 group-hover:to-indigo-100/50 transition-all duration-500"></div>
                  
                  <div className="relative z-10">
                    <div className="flex items-center mb-6">
                      <div className="relative">
                        <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-500 rounded-xl blur opacity-75 group-hover:opacity-100 transition-opacity duration-300"></div>
                        <div className="relative p-3 bg-gradient-to-r from-blue-500 to-purple-500 rounded-xl">
                          <UserIcon className="w-6 h-6 text-white" />
                        </div>
                      </div>
                      <div className="ml-4">
                        <h3 className="text-xl font-bold text-gray-900">ユーザー情報</h3>
                        <p className="text-sm text-gray-600">アカウント詳細</p>
                      </div>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="flex justify-between items-center p-3 bg-white/50 rounded-lg">
                        <span className="text-sm font-medium text-gray-600">ユーザー名</span>
                        <span className="text-sm font-semibold text-gray-900">{user.username}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-white/50 rounded-lg">
                        <span className="text-sm font-medium text-gray-600">メールアドレス</span>
                        <span className="text-sm font-semibold text-gray-900 truncate ml-2">{user.email}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-white/50 rounded-lg">
                        <span className="text-sm font-medium text-gray-600">作成日</span>
                        <span className="text-sm font-semibold text-gray-900">{formatDate(user.created_at)}</span>
                      </div>
                    </div>
                  </div>
                  
                  {/* Decorative elements */}
                  <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-blue-400/20 to-purple-400/20 rounded-full blur-xl"></div>
                  <div className="absolute bottom-0 left-0 w-16 h-16 bg-gradient-to-tr from-indigo-400/20 to-pink-400/20 rounded-full blur-lg"></div>
                </div>
              </div>

              {/* Social Accounts Section */}
              <div className="lg:col-span-2">
                <div className="relative bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-green-50/30 to-emerald-50/30"></div>
                  <div className="relative z-10 p-6">
                    <SocialAccountsSection key={socialLinkedKey} />
                  </div>
                </div>
              </div>
            </div>

            {/* WebAuthn Credentials Section */}
            <div className="relative bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-emerald-50/30 to-teal-50/30"></div>
              <div className="relative z-10 p-6">
                <WebAuthnCredentialsSection />
              </div>
            </div>

            {/* Token Management */}
            <div className="relative bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-violet-50/30 to-purple-50/30"></div>
              
              <div className="relative z-10 p-6">
                <div className="flex items-center mb-6">
                  <div className="relative">
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl blur opacity-75"></div>
                    <div className="relative p-3 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl">
                      <KeyIcon className="w-6 h-6 text-white" />
                    </div>
                  </div>
                  <div className="ml-4">
                    <h3 className="text-2xl font-bold text-gray-900">認証・アクセス管理</h3>
                    <p className="text-sm text-gray-600">OAuth2クライアント・APIキー・ドキュメント</p>
                  </div>
                </div>

                {/* Auth Method Tabs */}
                <div className="mb-8">
                  <div className="flex flex-wrap gap-2 p-1 bg-gray-100/50 rounded-2xl backdrop-blur-sm">
                    {[
                      { id: 'overview', label: '概要', icon: ChartBarIcon, gradient: 'from-blue-500 to-cyan-500' },
                      { id: 'oauth2', label: 'OAuth2', icon: ShieldCheckIcon, gradient: 'from-green-500 to-emerald-500' },
                      { id: 'apikeys', label: 'APIキー', icon: KeyIcon, gradient: 'from-purple-500 to-pink-500' },
                      { id: 'docs', label: 'ドキュメント', icon: LightBulbIcon, gradient: 'from-orange-500 to-red-500' }
                    ].map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => setAuthTab(tab.id as typeof authTab)}
                        className={`flex items-center justify-center gap-2 px-4 py-3 rounded-xl font-medium transition-all duration-300 flex-1 min-w-0 ${
                          authTab === tab.id 
                            ? `bg-gradient-to-r ${tab.gradient} text-white shadow-lg transform scale-105` 
                            : 'text-gray-600 hover:text-gray-900 hover:bg-white/50'
                        }`}
                      >
                        <tab.icon className="w-4 h-4 flex-shrink-0" />
                        <span className="truncate text-sm md:text-base">{tab.label}</span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Auth Content Based on Selected Tab */}
                {authTab === 'overview' && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                    {/* OAuth2 Overview Card */}
                    <div className="group relative bg-white/60 backdrop-blur-sm rounded-2xl p-6 border border-white/20 hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-2">
                      <div className="absolute inset-0 bg-gradient-to-br from-green-50/50 to-emerald-50/50 rounded-2xl group-hover:from-green-100/60 group-hover:to-emerald-100/60 transition-all duration-500"></div>
                      
                      <div className="relative z-10">
                        <div className="flex items-center mb-4">
                          <div className="p-3 bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl">
                            <ShieldCheckIcon className="w-6 h-6 text-white" />
                          </div>
                          <div className="ml-3">
                            <h4 className="text-xl font-bold text-gray-900">OAuth2クライアント</h4>
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">推奨</span>
                          </div>
                        </div>
                        
                        <p className="text-gray-600 mb-4 leading-relaxed">
                          Webアプリ、モバイルアプリなどの標準的な認証フロー。
                          ユーザーの明示的な許可を得て、セキュアにアクセス。
                        </p>
                        
                        <div className="grid grid-cols-2 gap-3 mb-6">
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">セキュアフロー</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">明示的許可</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">自動更新</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">スコープ制御</span>
                          </div>
                        </div>
                        
                        <button
                          onClick={() => setAuthTab('oauth2')}
                          className="w-full py-3 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white rounded-xl font-medium transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          OAuth2クライアントを管理
                        </button>
                      </div>
                    </div>

                    {/* API Key Overview Card */}
                    <div className="group relative bg-white/60 backdrop-blur-sm rounded-2xl p-6 border border-white/20 hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-2">
                      <div className="absolute inset-0 bg-gradient-to-br from-amber-50/50 to-orange-50/50 rounded-2xl group-hover:from-amber-100/60 group-hover:to-orange-100/60 transition-all duration-500"></div>
                      
                      <div className="relative z-10">
                        <div className="flex items-center mb-4">
                          <div className="p-3 bg-gradient-to-r from-amber-500 to-orange-500 rounded-xl">
                            <KeyIcon className="w-6 h-6 text-white" />
                          </div>
                          <div className="ml-3">
                            <h4 className="text-xl font-bold text-gray-900">APIキー</h4>
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-amber-100 text-amber-800">注意して使用</span>
                          </div>
                        </div>
                        
                        <p className="text-gray-600 mb-4 leading-relaxed">
                          サーバー間通信、スクリプト、CI/CDなどの直接アクセス。
                          有効期限なしで動作するため、適切な管理が必要。
                        </p>
                        
                        <div className="grid grid-cols-2 gap-3 mb-6">
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-amber-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">直接アクセス</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-amber-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">有効期限なし</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-amber-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">サーバー間通信</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-amber-500 rounded-full"></div>
                            <span className="text-sm text-gray-600">定期更新推奨</span>
                          </div>
                        </div>
                        
                        <button
                          onClick={() => setAuthTab('apikeys')}
                          className="w-full py-3 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white rounded-xl font-medium transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          APIキーを管理
                        </button>
                      </div>
                    </div>
                  </div>
                )}

              {authTab === 'oauth2' && (
                <OAuth2ClientsSection />
              )}

              {authTab === 'docs' && (
                <ApiDocumentation />
              )}

              {authTab === 'apikeys' && (
                <div>
                  {/* API Key Creation */}
                  <div style={{
                    backgroundColor: '#f9fafb',
                    borderRadius: '0.5rem',
                    padding: '1rem',
                    marginBottom: '1.5rem'
                  }}>
                    <h4 style={{
                      fontSize: '1rem',
                      fontWeight: 500,
                      color: '#1f2937',
                      marginBottom: '0.5rem'
                    }}>
                      新しいAPIキーを作成
                    </h4>
                    <p style={{
                      fontSize: '0.75rem',
                      color: '#6b7280',
                      marginBottom: '1rem',
                      lineHeight: 1.4
                    }}>
                      APIキーは外部アプリケーションがあなたのアカウントにアクセスするために使用されます。
                      信頼できるアプリケーションにのみ発行し、不要になったら削除してください。
                    </p>
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <div style={{ flex: 1, minWidth: '200px' }}>
                        <label style={{
                          display: 'block',
                          fontSize: '0.75rem',
                          fontWeight: 500,
                          color: '#374151',
                          marginBottom: '0.25rem'
                        }}>
                          APIキー名
                        </label>
                        <input
                          type="text"
                          placeholder="例：モバイルアプリ、CI/CD、分析ツール"
                          value={apiKeyName}
                          onChange={(e) => setApiKeyName(e.target.value)}
                          maxLength={100}
                          className="form-input"
                        />
                        <p style={{
                          fontSize: '0.625rem',
                          color: '#9ca3af',
                          marginTop: '0.25rem'
                        }}>
                          このAPIキーの用途を分かりやすく記述してください
                        </p>
                      </div>
                      <button
                        onClick={createApiKey}
                        disabled={!apiKeyName.trim() || creatingApiKey}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '0.5rem 1rem',
                          border: 'none',
                          fontSize: '0.875rem',
                          fontWeight: 500,
                          borderRadius: '0.375rem',
                          color: 'white',
                          backgroundColor: 'var(--color-primary-600)',
                          cursor: creatingApiKey || !apiKeyName.trim() ? 'not-allowed' : 'pointer',
                          opacity: creatingApiKey || !apiKeyName.trim() ? 0.5 : 1,
                          transition: 'background-color 0.2s'
                        }}
                        onMouseOver={(e) => {
                          if (!creatingApiKey && apiKeyName.trim()) {
                            (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-700)';
                          }
                        }}
                        onMouseOut={(e) => {
                          if (!creatingApiKey && apiKeyName.trim()) {
                            (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-600)';
                          }
                        }}
                      >
                        <PlusIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
                        {creatingApiKey ? '作成中...' : 'APIキーを作成'}
                      </button>
                    </div>
                  </div>

                  {error && (
                    <div className="error-message" style={{ marginBottom: '1.5rem' }}>
                      {error}
                    </div>
                  )}

                  {/* Tokens List */}
                  <div>
                    <h4 style={{
                      fontSize: '1rem',
                      fontWeight: 500,
                      color: '#1f2937',
                      marginBottom: '1rem'
                    }}>
                      既存のトークン
                    </h4>
                    {loading ? (
                      <div style={{ textAlign: 'center', padding: '2rem' }}>
                        <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>読み込み中...</div>
                      </div>
                    ) : tokens.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '2rem' }}>
                        <KeyIcon style={{
                          width: '3rem',
                          height: '3rem',
                          margin: '0 auto 0.5rem',
                          color: '#d1d5db'
                        }} />
                        <h3 style={{
                          fontSize: '0.875rem',
                          fontWeight: 500,
                          color: '#1f2937',
                          margin: '0.5rem 0 0.25rem 0'
                        }}>
                          トークンがありません
                        </h3>
                        <p style={{
                          fontSize: '0.875rem',
                          color: '#6b7280',
                          margin: 0
                        }}>
                          新しいAPIキーを作成してください
                        </p>
                      </div>
                    ) : (
                      <div style={{
                        display: 'flex',
                        flexDirection: 'row',
                        gap: '1rem',
                        flexWrap: 'wrap'
                      }}>
                        {tokens.map((token) => (
                          <div
                            key={token.id}
                            style={{
                              border: '1px solid #e5e7eb',
                              borderRadius: '0.5rem',
                              padding: '1rem',
                              transition: 'box-shadow 0.2s',
                              flex: '1 1 300px',
                              minWidth: '300px'
                            }}
                            onMouseOver={(e) => {
                              (e.currentTarget as HTMLElement).style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1)';
                            }}
                            onMouseOut={(e) => {
                              (e.currentTarget as HTMLElement).style.boxShadow = 'none';
                            }}
                          >
                            <div style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              marginBottom: '0.75rem'
                            }}>
                              <h5 style={{
                                fontSize: '0.875rem',
                                fontWeight: 500,
                                color: '#1f2937',
                                margin: 0
                              }}>
                                {token.name}
                              </h5>
                              <span style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                padding: '0.25rem 0.625rem',
                                borderRadius: '9999px',
                                fontSize: '0.75rem',
                                fontWeight: 500,
                                backgroundColor: token.token_type === 'api_key' ? '#dbeafe' : '#f3e8ff',
                                color: token.token_type === 'api_key' ? '#1d4ed8' : '#7c3aed'
                              }}>
                                {token.token_type === 'api_key' ? 'APIキー' : 'セッション'}
                              </span>
                            </div>
                            <div style={{
                              fontSize: '0.75rem',
                              color: '#6b7280',
                              marginBottom: '0.75rem',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '0.5rem'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center' }}>
                                <TagIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                                <span style={{ fontWeight: 500 }}>スコープ:</span>
                                <span style={{ marginLeft: '0.25rem' }}>{token.scopes.join(', ')}</span>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center' }}>
                                <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                                <span style={{ fontWeight: 500 }}>作成日:</span>
                                <span style={{ marginLeft: '0.25rem' }}>{formatDate(token.created_at)}</span>
                              </div>
                              {token.last_used_at && (
                                <div style={{ display: 'flex', alignItems: 'center' }}>
                                  <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                                  <span style={{ fontWeight: 500 }}>最終使用:</span>
                                  <span style={{ marginLeft: '0.25rem' }}>{formatDate(token.last_used_at)}</span>
                                </div>
                              )}
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                              <button
                                onClick={() => revokeToken(token.id)}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  padding: '0.25rem 0.75rem',
                                  border: 'none',
                                  fontSize: '0.875rem',
                                  fontWeight: 500,
                                  borderRadius: '0.375rem',
                                  color: '#b91c1c',
                                  backgroundColor: '#fef2f2',
                                  cursor: 'pointer',
                                  transition: 'background-color 0.2s'
                                }}
                                onMouseOver={(e) => {
                                  (e.currentTarget as HTMLElement).style.backgroundColor = '#fecaca';
                                }}
                                onMouseOut={(e) => {
                                  (e.currentTarget as HTMLElement).style.backgroundColor = '#fef2f2';
                                }}
                              >
                                <TrashIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                                無効化
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Modern API Key Modal */}
      {newApiKey && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="relative bg-white/90 backdrop-blur-xl rounded-3xl shadow-2xl max-w-lg w-full border border-white/20 overflow-hidden">
            {/* Animated background */}
            <div className="absolute inset-0 bg-gradient-to-br from-green-50/30 to-emerald-50/30"></div>
            
            <div className="relative z-10 p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <div className="p-3 bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl">
                    <SparklesIcon className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-gray-900">APIキーが作成されました</h3>
                    <p className="text-sm text-gray-600">新しいAPIキーの準備完了</p>
                  </div>
                </div>
                <button
                  onClick={closeApiKeyModal}
                  className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-xl transition-all duration-200"
                >
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>
              
              <div className="mb-6">
                <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl mb-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <BoltIcon className="w-5 h-5 text-amber-500" />
                    <span className="font-medium text-amber-800">重要な注意事項</span>
                  </div>
                  <p className="text-sm text-amber-700">
                    このAPIキーは一度のみ表示されます。安全な場所に保存し、他の人と共有しないでください。
                  </p>
                </div>
                
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-gray-100 to-gray-200 rounded-xl blur"></div>
                  <div className="relative bg-gray-50/80 backdrop-blur-sm rounded-xl p-4 border border-gray-200">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-600">APIキー</span>
                      <button
                        onClick={() => navigator.clipboard.writeText(newApiKey)}
                        className="text-xs bg-blue-100 hover:bg-blue-200 text-blue-700 px-2 py-1 rounded-lg transition-colors duration-200"
                      >
                        コピー
                      </button>
                    </div>
                    <code className="text-sm font-mono text-gray-900 break-all block">
                      {newApiKey}
                    </code>
                  </div>
                </div>
              </div>
              
              <div className="flex space-x-3">
                <button
                  onClick={() => navigator.clipboard.writeText(newApiKey)}
                  className="flex-1 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 text-white rounded-xl font-medium transition-all duration-300 transform hover:scale-105 shadow-lg"
                >
                  クリップボードにコピー
                </button>
                <button
                  onClick={closeApiKeyModal}
                  className="flex-1 py-3 bg-gradient-to-r from-gray-100 to-gray-200 hover:from-gray-200 hover:to-gray-300 text-gray-700 rounded-xl font-medium transition-all duration-300 transform hover:scale-105"
                >
                  閉じる
                </button>
              </div>
            </div>
            
            {/* Decorative elements */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-green-400/10 to-emerald-400/10 rounded-full blur-2xl"></div>
            <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-blue-400/10 to-cyan-400/10 rounded-full blur-xl"></div>
          </div>
        </div>
      )}
    </>
  );
};

export default Dashboard;