import {
  createContext,
  useContext,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react';

interface AuthContextValue {
  userId: string | null;
  token: string | null;
  setCredentials: (userId: string, token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider = ({ children }: PropsWithChildren) => {
  const [userId, setUserId] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  const setCredentials = (nextUserId: string, nextToken: string) => {
    setUserId(nextUserId);
    setToken(nextToken);
  };

  const logout = () => {
    setUserId(null);
    setToken(null);
  };

  const value = useMemo(
    () => ({
      userId,
      token,
      setCredentials,
      logout,
    }),
    [userId, token],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

