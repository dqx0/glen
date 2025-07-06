import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import SocialLoginSection from './SocialLoginSection';

const Register: React.FC = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const { register, loading, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username || !email || !password || !confirmPassword) {
      return;
    }

    if (password !== confirmPassword) {
      alert('パスワードが一致しません');
      return;
    }

    if (password.length < 8) {
      alert('パスワードは8文字以上で入力してください');
      return;
    }

    try {
      await register(username, email, password);
      navigate('/dashboard');
    } catch (error) {
      // エラーはAuthContextで処理済み
      console.error('Registration failed:', error);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="text-center mb-8">
          <h1 className="auth-title">Glen ID</h1>
          <p className="auth-subtitle">新しいアカウントを作成</p>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="username" className="form-label">
              ユーザー名
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
              placeholder="ユーザー名を入力"
              className="form-input"
            />
          </div>
          
          <div>
            <label htmlFor="email" className="form-label">
              メールアドレス
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              placeholder="メールアドレスを入力"
              className="form-input"
            />
          </div>
          
          <div>
            <label htmlFor="password" className="form-label">
              パスワード
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="new-password"
                placeholder="パスワードを入力 (8文字以上)"
                className="form-input pr-12"
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 flex items-center pr-3"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeSlashIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                ) : (
                  <EyeIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                )}
              </button>
            </div>
          </div>
          
          <div>
            <label htmlFor="confirmPassword" className="form-label">
              パスワード（確認）
            </label>
            <div className="relative">
              <input
                id="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                placeholder="パスワードを再入力"
                className="form-input pr-12"
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 flex items-center pr-3"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? (
                  <EyeSlashIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                ) : (
                  <EyeIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                )}
              </button>
            </div>
          </div>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className="btn-primary"
            disabled={loading || !username || !email || !password || !confirmPassword}
          >
            {loading ? 'アカウント作成中...' : 'アカウントを作成'}
          </button>
        </form>

        {/* ソーシャルログイン */}
        <SocialLoginSection 
          onError={(error) => {
            console.error('Social login error:', error);
          }}
          disabled={loading}
        />

        <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
          <p style={{ fontSize: '0.875rem', color: '#6b7280' }}>
            既にアカウントをお持ちの場合は{' '}
            <Link 
              to="/login" 
              style={{ 
                fontWeight: 500, 
                color: 'var(--color-primary-600)', 
                textDecoration: 'none' 
              }}
            >
              ログイン
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;