FROM node:22-alpine
WORKDIR /app
COPY server.js ./server.js
ENV NODE_ENV=production
ENV SCANNER_PORT=4000
ENV SCANNER_HOST=0.0.0.0
USER node
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD node -e "fetch('http://127.0.0.1:4000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
