import { Router } from 'express';
import logger from '@/config/logger';
import { MESSAGES, HTTP_STATUS, ERROR_TYPES, NOT_IMPLEMENTED } from '@/constants';

const router = Router();

// Placeholder routes - to be implemented in Task 4

router.post('/', (req, res) => {
  logger.info(MESSAGES.REQUESTS.CHAT_REQUEST_RECEIVED, { ip: req.ip });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.CHAT_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

router.get('/:sessionId/history', (req, res) => {
  logger.info(MESSAGES.REQUESTS.CHAT_HISTORY_REQUESTED, { 
    ip: req.ip, 
    sessionId: req.params.sessionId 
  });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.CHAT_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

router.post('/:sessionId/end', (req, res) => {
  logger.info(MESSAGES.REQUESTS.CHAT_SESSION_END_REQUESTED, { 
    ip: req.ip, 
    sessionId: req.params.sessionId 
  });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.CHAT_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

router.delete('/:sessionId/history', (req, res) => {
  logger.info(MESSAGES.REQUESTS.CHAT_HISTORY_DELETION_REQUESTED, { 
    ip: req.ip, 
    sessionId: req.params.sessionId 
  });
  res.status(HTTP_STATUS.NOT_IMPLEMENTED).json({
    error: ERROR_TYPES.NOT_IMPLEMENTED,
    message: NOT_IMPLEMENTED.CHAT_ENDPOINTS,
    timestamp: new Date().toISOString(),
  });
});

export default router; 