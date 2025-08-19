import { Router } from 'express';
import logger from '@/config/logger';
import { MESSAGES, HTTP_STATUS, ERROR_TYPES, NOT_IMPLEMENTED } from '@/constants';

const router = Router();

// Placeholder routes - to be implemented in Task 8

router.get('/users', (req, res) => {
  logger.info(MESSAGES.REQUESTS.ADMIN_USERS_LIST_REQUESTED, { ip: req.ip });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.ADMIN_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

router.post('/features', (req, res) => {
  logger.info(MESSAGES.REQUESTS.ADMIN_FEATURE_FLAG_CREATION_REQUESTED, { ip: req.ip });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.ADMIN_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

router.get('/metrics', (req, res) => {
  logger.info(MESSAGES.REQUESTS.ADMIN_METRICS_REQUESTED, { ip: req.ip });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.ADMIN_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

export default router; 