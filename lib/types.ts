export interface Device { id: string; claimedAt: number; loggedOut: boolean }
export interface License {
  id: string; label: string;
  status: 'pending' | 'active' | 'logged_out' | 'expired' | 'disabled' | 'reset_required' | 'revoked';
  expiresAt: number; activatedAt: number; maxDevices: number; durationMs?: number;
  devices: Device[];
  reset: { used: number; limit: number; remaining: number; nextAllowedAt: number };
}
export interface User { uid: string; email: string }
export interface Session {
  sid: string;
  user: User; idToken: string; refreshToken: string; tokenExpiresAt: number;
  createdAt: number; expiresAt: number; authTime: number; demo?: boolean;
  licenseKey?: string;
}
