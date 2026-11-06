import { Router, Request, Response } from 'express';
import { createHash } from 'crypto';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import { prisma } from '@dct-crm/db';
import { loginSchema } from '@dct-crm/shared';
import jwt from 'jsonwebtoken';
import { generateToken, authenticate, AuthRequest } from '../middleware/auth';
import {
  allowHeartbeat,
  endSessionById,
  endSessionBySecret,
  getPresenceSettings,
  hashSessionSecret,
  isSessionOnline,
  maskIp,
  newSessionSecret,
  openUserSession,
  markSessionStale,
  touchUserSession,
  REFRESH_TOKEN_TTL_MS,
} from '../services/userPresence';
import { endImpersonation, impersonationExpirySeconds, loadImpersonation } from '../services/impersonation';
import { EffectivePermissionService } from '../services/effectivePermissions';
import { clearRefreshTokenCookie, refreshCookieName, setRefreshTokenCookie } from '../services/sessionTokens';

const router = Router();
const TRANSIENT_DATABASE_ERROR_CODES = new Set([
  'P1001',
  'P1002',
  'P1008',
  'P1010',
  'P1017',
  'P2024',
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EPIPE',
]);
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  skipSuccessfulRequests: true,
  requestWasSuccessful: (_req, res) => res.statusCode < 400 || res.statusCode >= 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return `login:${createHash('sha256').update(email || 'invalid-login').digest('hex')}`;
  },
});
const heartbeatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const authReq = req as AuthRequest;
    return `heartbeat:${authReq.sessionSecret
      ? hashSessionSecret(authReq.sessionSecret)
      : authReq.user?.id || 'anonymous'}`;
  },
});

function toObjectAccessKey(moduleName: string): string {
  const cleaned = (moduleName || '').trim();
  if (!cleaned) return cleaned;

  return cleaned
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1).toLowerCase())
    .join('');
}

function buildObjectPermissionMap(effectivePermissions: Array<{ name: string; module: string }>) {
  const permissions: Record<string, { create: boolean; read: boolean; update: boolean; delete: boolean; viewAll: boolean; modifyAll: boolean }> = {};

  for (const permission of effectivePermissions) {
    const objectKey = toObjectAccessKey(permission.module);
    if (!objectKey) continue;

    const current = permissions[objectKey] || {
      create: false,
      read: false,
      update: false,
      delete: false,
      viewAll: false,
      modifyAll: false,
    };

    const permissionName = permission.name.toUpperCase();
    if (permissionName.endsWith('_CREATE')) current.create = true;
    if (permissionName.endsWith('_READ') || permissionName.endsWith('_VIEW')) current.read = true;
    if (permissionName.endsWith('_UPDATE') || permissionName.endsWith('_EDIT')) current.update = true;
    if (permissionName.endsWith('_DELETE') || permissionName.endsWith('_DELECT')) current.delete = true;
    if (permissionName.endsWith('_VIEW_ALL')) current.viewAll = true;
    if (permissionName.endsWith('_MODIFY_ALL')) current.modifyAll = true;

    permissions[objectKey] = current;
  }

  return permissions;
}

router.post('/login', loginLimiter, async (req: Request, res: Response) => {
  const startedAt = Date.now();
  try {
    const { email, password } = loginSchema.parse(req.body);
    const normalizedEmail = email.trim().toLowerCase();

    if (!process.env.DATABASE_URL) {
      return res.status(503).json({
        success: false,
        error: 'CRM database is not configured. Add DATABASE_URL to the CRM .env file and restart the API.',
      });
    }
    if (!process.env.JWT_SECRET) {
      return res.status(503).json({
        success: false,
        error: 'CRM authentication is not configured. Add JWT_SECRET to the CRM .env file and restart the API.',
      });
    }

    const users = await prisma.user.findMany({
      where: { email: normalizedEmail, isActive: true },
      include: {
        tenant: { select: { id: true, name: true, slug: true, isActive: true, companyStartDate: true, companyExpiryDate: true } },
        profile: { select: { id: true, name: true, description: true, isAdmin: true, leadStatusAccess: true } },
        roles: {
          include: {
            role: {
              include: {
                permissionSets: {
                  include: { permissionSet: true },
                },
              },
            },
          },
        },
      },
    });

    let user: (typeof users)[number] | undefined;
    for (const candidate of users) {
      if (await bcrypt.compare(password, candidate.passwordHash)) {
        user = candidate;
        break;
      }
    }

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    if (!user.tenant.isActive) {
      return res.status(403).json({ success: false, error: 'Company is deactivated. Contact your administrator.' });
    }

    if (!user.isSuperAdmin) {
      const now = new Date();
      if (user.tenant.companyStartDate && now < user.tenant.companyStartDate) {
        return res.status(403).json({ success: false, error: 'Company has not started yet. Access begins on ' + user.tenant.companyStartDate.toLocaleDateString() + '.' });
      }
      if (user.tenant.companyExpiryDate && now > user.tenant.companyExpiryDate) {
        return res.status(403).json({ success: false, error: 'Company subscription has expired. Contact Super Admin.' });
      }
    }

    const sessionSecret = newSessionSecret();
    const refreshToken = newSessionSecret();
    const refreshTokenExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    const loginAt = Date.now();

    const token = generateToken({
      id: user.id,
      email: user.email,
      tenantId: user.tenantId,
      isSuperAdmin: user.isSuperAdmin,
      loginAt,
      sessionId: sessionSecret,
    });

    const effectivePerms = await EffectivePermissionService.getEffectivePermissions(user.id);
    const objectPermissions = buildObjectPermissionMap(effectivePerms);

    const hasFullAccess = effectivePerms.some((p) => p.name === 'FULL_SYSTEM_ACCESS');
    const granularPermissions: Record<string, string[]> = {};
    for (const perm of effectivePerms) {
      if (!granularPermissions[perm.module]) granularPermissions[perm.module] = [];
      granularPermissions[perm.module].push(perm.name);
    }

    await openUserSession({
      userId: user.id,
      tenantId: user.tenantId,
      sessionSecret,
      refreshTokenSecret: refreshToken,
      refreshTokenExpiresAt,
      req,
      isImpersonation: false,
    });

    let companyLifecycleStatus = 'active';
    if (user.tenant) {
      const now = new Date();
      if (!user.tenant.isActive) companyLifecycleStatus = 'deactivated';
      else if (user.tenant.companyStartDate && now < user.tenant.companyStartDate) companyLifecycleStatus = 'pending';
      else if (user.tenant.companyExpiryDate && now > user.tenant.companyExpiryDate) companyLifecycleStatus = 'expired';
    }

    setRefreshTokenCookie(res, sessionSecret, refreshToken, refreshTokenExpiresAt);
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          avatar: user.avatar,
          isSuperAdmin: user.isSuperAdmin,
        },
        profile: user.profile ? { ...user.profile, isAdmin: !!user.profile.isAdmin } : null,
        tenant: {
          ...user.tenant,
          companyLifecycleStatus,
        },
        roles: user.roles.map((ur) => ur.role.name),
        permissions: objectPermissions,
        effectivePermissions: effectivePerms.map((p) => p.name),
        effectivePermissionsByModule: granularPermissions,
        hasFullAccess,
      },
    });
  } catch (error: any) {
    const errorCode = error && typeof error === 'object'
      ? 'errorCode' in error
        ? String(error.errorCode)
        : 'code' in error
          ? String(error.code)
          : undefined
      : undefined;
    const errorName = error instanceof Error ? error.name : 'UnknownError';
    const databaseUnavailable = TRANSIENT_DATABASE_ERROR_CODES.has(errorCode || '') ||
      errorCode === 'P1000' ||
      (error instanceof Error && error.message.includes('Authentication failed against database server'));
    console.error(JSON.stringify({
      event: 'auth.login.failed',
      errorName,
      errorCode: errorCode || null,
      status: databaseUnavailable ? 503 : 500,
      durationMs: Date.now() - startedAt,
    }));
    if (error.name === 'ZodError') {
      return res.status(400).json({ success: false, error: error.errors[0].message });
    }
    if (error instanceof Error && error.message.includes('Environment variable not found: DATABASE_URL')) {
      return res.status(503).json({
        success: false,
        error: 'CRM database is not configured. Add DATABASE_URL to the CRM .env file and restart the API.',
      });
    }
    if (['P1000', 'P1001', 'P1002', 'P1010'].includes(errorCode || '')) {
      return res.status(503).json({
        success: false,
        error: errorCode === 'P1000'
          ? 'PostgreSQL rejected the credentials in DATABASE_URL. Update the local CRM .env with the correct database password.'
          : 'Unable to connect to the CRM database. Check DATABASE_URL and confirm PostgreSQL is running.',
      });
    }
    if (databaseUnavailable) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service temporarily unavailable. Please try again.',
      });
    }
    if (
      error instanceof Error &&
      error.message.includes('Authentication failed against database server')
    ) {
      return res.status(503).json({
        success: false,
        error: 'PostgreSQL rejected the credentials in DATABASE_URL. Update the local CRM .env with the correct database password.',
      });
    }
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

router.post('/logout', async (req: Request, res: Response) => {
  const header = req.headers.authorization;
  const bodyToken = typeof req.body?.token === 'string' ? req.body.token : undefined;
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : bodyToken;
  let decoded: { isImpersonation?: boolean; impersonationId?: string; id?: string; isSuperAdmin?: boolean; sid?: string } | undefined;
  if (token && process.env.JWT_SECRET) {
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true }) as typeof decoded;
    } catch {
      // An expired or invalid token still clears the browser session.
    }
  }
  if (decoded) {
    try {
      if (decoded.sid) await endSessionBySecret(decoded.sid, 'LOGOUT');
      if (decoded.isImpersonation && decoded.impersonationId) {
        await endImpersonation(decoded.impersonationId, 'logout');
      } else if (decoded.isSuperAdmin && decoded.id) {
        await prisma.impersonationSession.updateMany({
          where: { superadminId: decoded.id, endedAt: null },
          data: { endedAt: new Date(), endReason: 'logout' },
        });
      }
    } catch (error) {
      console.error('Session logout failed:', error instanceof Error ? error.name : 'unknown error');
      if (decoded.sid) clearRefreshTokenCookie(res, decoded.sid);
      res.clearCookie('token', { httpOnly: true, expires: new Date(0), path: '/' });
      return res.status(503).json({ success: false, error: 'Unable to revoke the session right now' });
    }
    if (decoded.sid) clearRefreshTokenCookie(res, decoded.sid);
  }
  res.clearCookie('token', { httpOnly: true, expires: new Date(0), path: '/' });
  res.json({ success: true, message: 'Logged out successfully' });
});

router.post('/refresh', async (req: Request, res: Response) => {
  const authorizationHeader = req.headers.authorization;
  const accessToken = authorizationHeader?.startsWith('Bearer ')
    ? authorizationHeader.slice('Bearer '.length)
    : undefined;
  if (!accessToken || !process.env.JWT_SECRET) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  let decoded: {
    id: string;
    email: string;
    tenantId: string;
    isSuperAdmin: boolean;
    impersonatedBy?: string;
    loginAt?: number;
    sid?: string;
    isImpersonation?: boolean;
    impersonationId?: string;
    viewOnly?: boolean;
  };
  try {
    decoded = jwt.verify(accessToken, process.env.JWT_SECRET, { ignoreExpiration: true }) as typeof decoded;
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Invalid access token' });
  }
  if (!decoded.sid || !decoded.id || !decoded.tenantId) {
    return res.status(401).json({ success: false, error: 'Session cannot be refreshed' });
  }

  let cookieName: string;
  try {
    cookieName = refreshCookieName(decoded.sid);
  } catch {
    return res.status(401).json({ success: false, error: 'Session cannot be refreshed' });
  }
  const refreshToken = req.cookies?.[cookieName];
  if (typeof refreshToken !== 'string' || !refreshToken) {
    return res.status(401).json({ success: false, error: 'Refresh token is missing or expired' });
  }

  try {
    const now = new Date();
    const session = await prisma.userSession.findUnique({
      where: { sessionTokenHash: hashSessionSecret(decoded.sid) },
      select: {
        id: true,
        userId: true,
        tenantId: true,
        endedAt: true,
        endReason: true,
        isImpersonation: true,
        refreshTokenHash: true,
        refreshTokenExpiresAt: true,
      },
    });
    const currentRefreshHash = hashSessionSecret(refreshToken);
    if (
      !session ||
      session.userId !== decoded.id ||
      session.tenantId !== decoded.tenantId ||
      session.isImpersonation !== Boolean(decoded.isImpersonation) ||
      session.refreshTokenHash !== currentRefreshHash ||
      !session.refreshTokenExpiresAt ||
      session.refreshTokenExpiresAt <= now ||
      (session.endedAt && session.endReason !== 'IDLE_TIMEOUT')
    ) {
      return res.status(401).json({ success: false, error: 'Refresh token is invalid or expired' });
    }

    const impersonation = decoded.isImpersonation ? await loadImpersonation(decoded) : null;
    if (decoded.isImpersonation && !impersonation) {
      return res.status(401).json({ success: false, error: 'Impersonation session has ended' });
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        tenantId: true,
        isActive: true,
        isSuperAdmin: true,
        tenant: { select: { isActive: true, companyStartDate: true, companyExpiryDate: true } },
      },
    });
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, error: 'User is no longer active' });
    }
    if (!user.tenant.isActive && !impersonation?.allowInactive) {
      return res.status(403).json({ success: false, error: 'Company is inactive. Contact Super Admin.' });
    }
    if (!user.isSuperAdmin && !impersonation?.allowInactive) {
      if (user.tenant.companyStartDate && now < user.tenant.companyStartDate) {
        return res.status(403).json({ success: false, error: 'Company has not started yet.' });
      }
      if (user.tenant.companyExpiryDate && now > user.tenant.companyExpiryDate) {
        return res.status(403).json({ success: false, error: 'Company subscription has expired.' });
      }
    }

    const sessionSecret = decoded.sid;
    const touched = await touchUserSession({
      userId: user.id,
      tenantId: session.tenantId,
      sessionSecret,
      req,
      isImpersonation: session.isImpersonation,
    });
    if (touched.blocked) {
      return res.status(401).json({ success: false, error: 'Session ended' });
    }

    const nextRefreshToken = newSessionSecret();
    const nextRefreshExpiry = session.isImpersonation
      ? session.refreshTokenExpiresAt
      : new Date(now.getTime() + REFRESH_TOKEN_TTL_MS);
    const rotated = await prisma.userSession.updateMany({
      where: {
        id: session.id,
        refreshTokenHash: currentRefreshHash,
        refreshTokenExpiresAt: { gt: now },
        OR: [{ endedAt: null }, { endReason: 'IDLE_TIMEOUT' }],
      },
      data: {
        refreshTokenHash: hashSessionSecret(nextRefreshToken),
        refreshTokenExpiresAt: nextRefreshExpiry,
      },
    });
    if (rotated.count !== 1) {
      return res.status(409).json({ success: false, error: 'Session refresh already completed', code: 'SESSION_REFRESHED' });
    }

    const token = generateToken({
      id: user.id,
      email: user.email,
      tenantId: user.tenantId,
      isSuperAdmin: impersonation ? false : user.isSuperAdmin,
      impersonatedBy: decoded.impersonatedBy,
      loginAt: decoded.loginAt,
      sessionId: sessionSecret,
      isImpersonation: Boolean(impersonation),
      impersonationId: impersonation?.id,
      viewOnly: impersonation?.viewOnly,
    }, impersonation ? impersonationExpirySeconds(impersonation.hardExpiresAt) : '15m');
    setRefreshTokenCookie(res, sessionSecret, nextRefreshToken, nextRefreshExpiry);
    return res.json({ success: true, data: { token } });
  } catch (error) {
    console.error('Session refresh failed:', error instanceof Error ? error.name : 'unknown error');
    return res.status(503).json({ success: false, error: 'Authentication service temporarily unavailable' });
  }
});

router.post('/leave', async (req: Request, res: Response) => {
  const token = typeof req.body?.token === 'string' ? req.body.token : undefined;
  if (token && process.env.JWT_SECRET) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET) as { sid?: string };
      if (decoded.sid) await markSessionStale(decoded.sid);
    } catch {
      // A closed tab can send an expired token. The idle sweep still applies.
    }
  }
  res.json({ success: true });
});

router.post('/heartbeat', authenticate, heartbeatLimiter, async (req: AuthRequest, res: Response) => {
  const settings = await getPresenceSettings(req.impersonation?.tenantId || req.user!.tenantId);
  if (!allowHeartbeat(req.user!.id)) {
    return res.json({ success: true, data: { skipped: true, nextInMs: settings.heartbeatIntervalSeconds * 1000 } });
  }
  const sessionSecret = req.sessionSecret || newSessionSecret();
  const impersonation = req.impersonation;
  try {
    const touched = await touchUserSession({
      userId: req.user!.id,
      tenantId: impersonation ? impersonation.tenantId : req.user!.tenantId,
      sessionSecret,
      req,
      isImpersonation: Boolean(impersonation),
    });
    if (touched.blocked) return res.status(401).json({ success: false, error: 'Session ended' });
  } catch (error) {
    console.error('Heartbeat error', error instanceof Error ? error.name : 'error');
    return res.status(500).json({ success: false, error: 'Heartbeat failed' });
  }
  const token = req.sessionSecret ? undefined : generateToken({
    id: req.user!.id,
    email: req.user!.email,
    tenantId: impersonation ? impersonation.tenantId : req.user!.tenantId,
    isSuperAdmin: impersonation ? false : req.user!.isSuperAdmin,
    impersonatedBy: req.user!.impersonatedBy,
    loginAt: req.sessionLoginAt,
    sessionId: sessionSecret,
    isImpersonation: Boolean(impersonation),
    impersonationId: impersonation?.id,
    viewOnly: impersonation?.viewOnly,
  }, impersonation ? impersonationExpirySeconds(impersonation.hardExpiresAt) : '15m');
  res.json({ success: true, data: { nextInMs: settings.heartbeatIntervalSeconds * 1000, ...(token ? { token } : {}) } });
});

router.get('/sessions', authenticate, async (req: AuthRequest, res: Response) => {
  const currentHash = req.sessionSecret ? hashSessionSecret(req.sessionSecret) : '';
  const settings = await getPresenceSettings(req.user!.tenantId);
  const now = new Date();
  const showFullIp = Boolean(req.user?.isAdmin || req.user?.isSuperAdmin);
  const rows = await prisma.userSession.findMany({
    where: { userId: req.user!.id, tenantId: req.user!.tenantId, endedAt: null, isImpersonation: false },
    orderBy: { lastSeenAt: 'desc' },
    select: { id: true, sessionTokenHash: true, browser: true, os: true, deviceType: true, ipAddress: true, createdAt: true, lastSeenAt: true },
  });
  res.json({
    success: true,
    data: rows
      .filter((row) => isSessionOnline({ id: row.id, endedAt: null, isImpersonation: false, lastSeenAt: row.lastSeenAt }, now, settings.idleTimeoutSeconds * 1000))
      .map(({ sessionTokenHash, ipAddress, ...row }) => ({
        ...row,
        ipAddress: showFullIp ? ipAddress : maskIp(ipAddress),
        current: sessionTokenHash === currentHash,
      })),
  });
});

router.post('/sessions/:id/end', authenticate, async (req: AuthRequest, res: Response) => {
  const owned = await prisma.userSession.findFirst({
    where: { id: req.params.id, userId: req.user!.id, tenantId: req.user!.tenantId, endedAt: null },
    select: { id: true },
  });
  if (!owned) return res.status(404).json({ success: false, error: 'Session not found' });
  await endSessionById(req.params.id, req.user!.tenantId, 'LOGOUT');
  res.json({ success: true });
});

router.post('/stop-impersonation', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user?.impersonatedBy) {
      return res.status(400).json({ success: false, error: 'You are not impersonating another user' });
    }

    const admin = await prisma.user.findFirst({
      where: { id: req.user.impersonatedBy, tenantId: req.tenantId!, isActive: true },
      select: { id: true, email: true, tenantId: true, isSuperAdmin: true },
    });
    if (!admin) {
      return res.status(401).json({ success: false, error: 'Original administrator session is unavailable' });
    }

    res.json({ success: true, data: { token: generateToken(admin) } });
  } catch (error) {
    console.error('Stop impersonation error:', error);
    res.status(500).json({ success: false, error: 'Failed to return to administrator' });
  }
});

router.get('/me', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        phone: true,
        avatar: true,
        isSuperAdmin: true,
        tenant: { select: { id: true, name: true, slug: true, logo: true, country: true, companyStartDate: true, companyExpiryDate: true, isActive: true } },
        profile: { select: { id: true, name: true, description: true, isAdmin: true, leadStatusAccess: true } },
        roles: {
          include: {
            role: {
              include: {
                permissionSets: {
                  include: { permissionSet: true },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const effectivePerms = await EffectivePermissionService.getEffectivePermissions(user.id);
    const objectPermissions = buildObjectPermissionMap(effectivePerms);

    const hasFullAccess = effectivePerms.some((p) => p.name === 'FULL_SYSTEM_ACCESS');
    const granularPermissions: Record<string, string[]> = {};
    for (const perm of effectivePerms) {
      if (!granularPermissions[perm.module]) granularPermissions[perm.module] = [];
      granularPermissions[perm.module].push(perm.name);
    }

    let companyLifecycleStatus = 'active';
    if (user.tenant) {
      const now = new Date();
      if (!user.tenant.isActive) companyLifecycleStatus = 'deactivated';
      else if (user.tenant.companyStartDate && now < user.tenant.companyStartDate) companyLifecycleStatus = 'pending';
      else if (user.tenant.companyExpiryDate && now > user.tenant.companyExpiryDate) companyLifecycleStatus = 'expired';
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          phone: user.phone,
          avatar: user.avatar,
          isSuperAdmin: user.isSuperAdmin,
          impersonatedBy: req.user?.impersonatedBy || null,
        },
        profile: user.profile ? { ...user.profile, isAdmin: !!user.profile.isAdmin } : null,
        tenant: user.tenant ? {
          ...user.tenant,
          companyLifecycleStatus,
        } : null,
        roles: user.roles.map((ur) => ur.role.name),
        permissions: objectPermissions,
        effectivePermissions: effectivePerms.map((p) => p.name),
        effectivePermissionsByModule: granularPermissions,
        hasFullAccess,
      },
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, error: 'Failed to get user' });
  }
});

export { router as authRoutes };