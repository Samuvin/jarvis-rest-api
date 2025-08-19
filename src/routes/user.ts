import { Router } from 'express';
import logger from '@/config/logger';
import { MESSAGES, HTTP_STATUS, ERROR_TYPES, NOT_IMPLEMENTED } from '@/constants';

const router = Router();

// Placeholder routes - to be implemented in Task 6

router.get('/me', (req, res) => {
  logger.info(MESSAGES.REQUESTS.USER_INFO_REQUESTED, { ip: req.ip });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.USER_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

export default router; 