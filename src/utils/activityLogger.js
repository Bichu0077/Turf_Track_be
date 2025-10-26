import crypto from 'crypto';
import { userActivities } from '../config/constants.js';

/**
 * Append user activity log
 */
export function appendUserActivity(userId, activity) {
  const maxItems = 100;
  const list = userActivities.get(userId) || [];
  const entry = {
    id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    type: activity.type,
    message: activity.message,
    details: activity.details || {},
    createdAt: new Date().toISOString()
  };
  list.unshift(entry);
  if (list.length > maxItems) list.length = maxItems;
  userActivities.set(userId, list);
  return entry;
}
