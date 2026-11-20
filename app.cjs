// Startup file for cPanel "Setup Node.js App" (Passenger)
// Loads the built ESM server from dist/server.js
import('./dist/server.js').catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
