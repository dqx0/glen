import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface PrivateRouteProps {
  children: React.ReactNode;
}

const PrivateRoute: React.FC<PrivateRouteProps> = ({ children }) => {
  const { user, loading } = useAuth();

  console.log('PrivateRoute - loading:', loading, 'user:', user);

  if (loading) {
    console.log('PrivateRoute - still loading, showing loading screen');
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        <div>読み込み中...</div>
      </div>
    );
  }

  if (user) {
    console.log('PrivateRoute - user authenticated, showing protected content');
    return <>{children}</>;
  } else {
    console.log('PrivateRoute - no user, redirecting to login');
    return <Navigate to="/login" replace />;
  }
};

export default PrivateRoute;