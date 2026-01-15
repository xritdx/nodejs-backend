const User = require("../models/User");
const onlineUsers = require("./onlineUsers");

const getAllUsers = async () => {
  const users = await User.find().select("-password");
  return users.map(user => {
    const data = user.toObject();
    data.isOnline = onlineUsers.isUserOnline(user._id);
    return data;
  });
};

module.exports = {
  getAllUsers
};
