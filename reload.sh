git pull
npm install --omit=dev
pm2 reload files || PORT=3004 pm2 start server.js --name files
