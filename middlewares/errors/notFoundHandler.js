const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Belə bir marşrut tapılmadı'
  });
};

module.exports = notFoundHandler;
