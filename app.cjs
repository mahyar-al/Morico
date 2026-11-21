// Startup file for cPanel "Setup Node.js App" (Passenger)
// Ensures NODE_ENV defaults to production unless explicitly overridden
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

// Loads the built ESM server from dist/server.js
import('./dist/server.js').catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
