# garment-admin-api worker

This is a standalone Cloudflare Worker project for the admin API.

## Files
- src/index.js - Worker entrypoint
- wrangler.toml - Worker config
- .gitignore - ignore build artifacts
- package.json - minimal dependencies

## Local development

```bash
npm install
npx wrangler dev
```

## Deploy to Cloudflare

```bash
npx wrangler deploy
```
