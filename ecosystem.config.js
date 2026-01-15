module.exports = {
  apps: [
    {
      name: "xritdx-erp-test-backend",
      script: "src/server.js", 
      instances: 1,
      exec_mode: "fork",
      env: {
        NODE_ENV: "production",
        PORT: 5009
      }
    }
  ]
};
