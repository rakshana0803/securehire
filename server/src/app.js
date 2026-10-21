import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import fs from 'node:fs';
import path from 'node:path';
import { config, ROOT } from './config.js';
import { authenticate } from './security.js';
import { ensureWeights } from './trust.js';
import { getSetting, setSetting } from './db.js';
import { DEMO_AADHAAR, AADHAAR_TEST_TRIGGERS, APAAR_REGISTRY } from './providers/mockData.js';
import { DEFAULT_RETENTION } from './services/retention.js';
import { semanticStatus } from './services/semantic.js';
import authRoutes from './routes/auth.js';
import candidateRoutes from './routes/candidate.js';
import assessmentRoutes from './routes/assessment.js';
import interviewRoutes from './routes/interview.js';
import offerRoutes from './routes/offer.js';
import recruiterRoutes from './routes/recruiter.js';
import securityRoutes from './routes/security.js';

export function initDefaults() {
  ensureWeights();
  if (!getSetting('retention_days')) setSetting('retention_days', DEFAULT_RETENTION);
  if (!getSetting('assessment_allowlist')) setSetting('assessment_allowlist', ['http://localhost:5173', 'http://127.0.0.1:5173']);
  if (!getSetting('monitoring_policy')) setSetting('monitoring_policy', { faceCheckSeconds: 10, focusEventsForReview: 3, focusWindowSeconds: 120, requireExtension: true, requireCameraMic: true, requireDesktopAgent: false });
  if (!getSetting('required_checks')) setSetting('required_checks', {
    enterprise: ['email', 'aadhaar', 'liveness', 'resume', 'assessment', 'interview'],
    contractor: ['email', 'aadhaar', 'liveness', 'resume'],
    remote: ['email', 'aadhaar', 'liveness', 'resume', 'assessment', 'interview', 'location'],
    'high-volume': ['email', 'aadhaar', 'assessment'],
    staffing: ['email', 'aadhaar', 'liveness', 'resume', 'interview'],
  });
}

export function createApp() {
  initDefaults();
  const app = express();
  app.set('trust proxy', config.trustProxy); // never trust arbitrary X-Forwarded-For
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    next();
  });
  // CORS: the web app origins, plus the SecureHire extension (chrome-extension://) for POST /api/events.
  app.use(cors({
    origin(origin, cb) {
      if (!origin || config.webOrigins.includes(origin) || origin.startsWith('chrome-extension://')) return cb(null, true);
      cb(null, false);
    },
    credentials: true,
  }));
  app.use(express.json({ limit: '200kb' }));
  app.use(cookieParser());
  app.use(authenticate);

  app.get('/api/health', (req, res) => res.json({ ok: true, service: 'securehire', time: new Date().toISOString(), semanticModel: semanticStatus().loaded }));
  app.get('/api/public/config', (req, res) => res.json({
    demoMode: config.demoMode,
    demo: config.demoMode ? {
      note: 'SYNTHETIC test data for the simulated providers.',
      aadhaar: DEMO_AADHAAR, aadhaarTriggers: AADHAAR_TEST_TRIGGERS, aadhaarOtp: '123456',
      apaarIds: Object.entries(APAAR_REGISTRY).map(([id, r]) => ({ id, label: `${r.degree.split(' in ')[0]} · ${r.institution.split(',')[0]} · ${r.graduationYear}`, name: r.name })),
      logins: [
        { role: 'recruiter', email: 'recruiter@securehire.dev', password: 'Demo@1234' },
        { role: 'admin', email: 'admin@securehire.dev', password: 'Demo@1234' },
        { role: 'candidate', email: 'priya@demo.securehire.dev', password: 'Demo@1234' },
      ],
    } : null,
  }));

  app.use('/api/auth', authRoutes);
  app.use('/api/me', candidateRoutes);
  app.use('/api', assessmentRoutes);
  app.use('/api', interviewRoutes);
  app.use('/api', offerRoutes);
  app.use('/api', recruiterRoutes);
  app.use('/api', securityRoutes);
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // Serve the built web app (single-service deployment option)
  const dist = path.resolve(ROOT, '..', 'web', 'dist');
  if (fs.existsSync(dist)) {
    app.use(express.static(dist, { index: false, maxAge: '1h' }));
    app.get('*', (req, res) => res.sendFile(path.join(dist, 'index.html')));
  }

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    const status = err.status || (err.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
    if (status >= 500) console.error(err);
    res.status(status).json({ error: status >= 500 ? 'Something went wrong on our side. Please try again.' : err.code === 'LIMIT_FILE_SIZE' ? 'File is larger than 5 MB.' : err.message });
  });
  return app;
}
