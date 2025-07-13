const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS設定
app.use(cors({
  origin: ['http://localhost:3000', 'https://glen.dqx0.com', 'https://api.glen.dqx0.com'],
  credentials: true
}));

// 静的ファイルの提供
app.use(express.static(path.join(__dirname)));

// ルートパスで index.html を提供
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// OAuth2 コールバックエンドポイント
app.get('/callback', (req, res) => {
  // クエリパラメータをそのまま index.html に渡すため、
  // index.html をリダイレクト付きで返す
  const queryString = req.url.split('?')[1] || '';
  const redirectUrl = `/?${queryString}`;
  res.redirect(redirectUrl);
});

// ヘルスチェック
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'glen-oauth2-sample-app'
  });
});

// 404ハンドラー
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    message: 'The requested resource was not found',
    path: req.path
  });
});

// エラーハンドラー
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: 'An unexpected error occurred'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Glen OAuth2 Sample App is running on http://localhost:${PORT}`);
  console.log(`📖 Open your browser and navigate to: http://localhost:${PORT}`);
  console.log(`🔗 OAuth2 callback URL: http://localhost:${PORT}/callback`);
  console.log(`💡 Make sure to configure your OAuth2 client with this callback URL`);
});