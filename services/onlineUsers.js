const EventEmitter = require('events');

const onlineUsers = new Map();
const emitter = new EventEmitter();

const toKey = userId => String(userId);

const emitStatusIfChanged = (userId, wasOnline, isOnline) => {
  if (wasOnline === isOnline) return;
  emitter.emit('statusChange', {
    userId: toKey(userId),
    isOnline
  });
};

const addOnlineUser = userId => {
  const key = toKey(userId);
  const count = onlineUsers.get(key) || 0;
  const wasOnline = count > 0;
  const nextCount = count + 1;
  onlineUsers.set(key, nextCount);
  emitStatusIfChanged(userId, wasOnline, nextCount > 0);
};

const removeOnlineUser = userId => {
  const key = toKey(userId);
  const count = onlineUsers.get(key);
  if (!count) return;
  const wasOnline = count > 0;
  const nextCount = count - 1;
  if (nextCount <= 0) {
    onlineUsers.delete(key);
  } else {
    onlineUsers.set(key, nextCount);
  }
  emitStatusIfChanged(userId, wasOnline, nextCount > 0);
};

const isUserOnline = userId => {
  const key = toKey(userId);
  return onlineUsers.has(key);
};

const getOnlineUserIds = () => Array.from(onlineUsers.keys());

const onStatusChange = listener => {
  emitter.on('statusChange', listener);
};

module.exports = {
  addOnlineUser,
  removeOnlineUser,
  isUserOnline,
  getOnlineUserIds,
  onStatusChange
};
