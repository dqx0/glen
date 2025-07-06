// エラーハンドリング用のユーティリティ関数

/**
 * unknown型のエラーオブジェクトから安全にエラーメッセージを取得する
 * @param error 未知のエラーオブジェクト
 * @param defaultMessage デフォルトのエラーメッセージ
 * @returns 安全なエラーメッセージ
 */
export function getErrorMessage(error: unknown, defaultMessage: string = 'エラーが発生しました'): string {
  if (error instanceof Error) {
    return error.message;
  }
  
  if (typeof error === 'string') {
    return error;
  }
  
  // APIレスポンスエラーの場合
  if (typeof error === 'object' && error !== null) {
    // axios風のエラーレスポンス
    if ('response' in error && typeof error.response === 'object' && error.response !== null) {
      if ('data' in error.response && typeof error.response.data === 'object' && error.response.data !== null) {
        if ('message' in error.response.data && typeof error.response.data.message === 'string') {
          return error.response.data.message;
        }
      }
    }
    
    // メッセージプロパティが存在する場合
    if ('message' in error && typeof error.message === 'string') {
      return error.message;
    }
  }
  
  return defaultMessage;
}

/**
 * unknown型のエラーオブジェクトが特定の型であるかを型安全に判定する
 * @param error 未知のエラーオブジェクト
 * @returns エラーオブジェクトがHTTPレスポンスエラーかどうか
 */
export function isHttpResponseError(error: unknown): error is { response: { data: { message: string } } } {
  return typeof error === 'object' && 
         error !== null && 
         'response' in error && 
         typeof error.response === 'object' && 
         error.response !== null && 
         'data' in error.response && 
         typeof error.response.data === 'object' && 
         error.response.data !== null && 
         'message' in error.response.data && 
         typeof error.response.data.message === 'string';
}