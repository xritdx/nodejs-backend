const globalErrorHandler = (err, req, res, next) => {
  console.error(err.stack);

  const statusCode = err.statusCode || 500;
  const message = err.message || 'Xəta baş verdi';

  const response = {
    success: false,
    message
  };

  if (process.env.NODE_ENV === 'development') {
    response.error = err.message;
  } else if (statusCode === 500) {
    response.error = 'Daxili server xətası';
  }

  res.status(statusCode).json(response);
};

module.exports = globalErrorHandler;
