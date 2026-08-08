const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Secret',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...corsHeaders,
    },
  });
}

function sanitizeName(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function normalizeRoute(pathname) {
  const cleaned = String(pathname || '').replace(/\/+$/, '') || '/';
  if (cleaned === '/api') return '/';
  if (cleaned.startsWith('/api/')) return cleaned.slice('/api'.length) || '/';
  return cleaned;
}

async function parseBody(request) {
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    try {
      return { type: 'json', value: await request.json() };
    } catch {
      return { type: 'json', value: {} };
    }
  }

  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    return { type: 'formData', value: await request.formData() };
  }

  return { type: 'none', value: {} };
}

function getBodyValue(data, key) {
  if (data instanceof FormData) return data.get(key);
  if (data && typeof data === 'object') return data[key];
  return '';
}

async function readCatalog(bucket) {
  const object = await bucket.get('product.json');
  if (!object) return [];

  const content = await object.text();
  if (!content) return [];

  try {
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeCatalog(bucket, products) {
  await bucket.put('product.json', JSON.stringify(products, null, 2), {
    cacheControl: 'public, max-age=31536000, immutable',
  });
  return products;
}

async function uploadImage(bucket, env, file, categoryId, productId) {
  const name = file?.name || 'image';
  const extension = (name.split('.').pop() || 'jpg').toLowerCase();
  const safeCategory = sanitizeName(categoryId) || 'product';
  const safeId = sanitizeName(productId) || 'item';
  const objectKey = `products/${safeCategory}-${safeId}.${extension}`;

  const arrayBuffer = await file.arrayBuffer();
  await bucket.put(objectKey, arrayBuffer, {
    httpMetadata: {
      contentType: file.type || 'application/octet-stream',
    },
    cacheControl: 'public, max-age=31536000, immutable',
  });

  return {
    objectKey,
    publicUrl: `${env.R2_PUBLIC_BASE_URL.replace(/\/$/, '')}/${objectKey.replace(/^\/+/, '')}`,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!env.GARMENT_BUCKET) {
      return jsonResponse({ success: false, error: 'The GARMENT_BUCKET binding is missing.' }, 500);
    }

    const providedSecret = request.headers.get('X-Admin-Secret') || '';
    if (providedSecret !== env.ADMIN_SECRET_KEY) {
      return jsonResponse({ success: false, error: 'Unauthorized' }, 401);
    }

    if (request.method !== 'POST') {
      return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
    }

    const bucket = env.GARMENT_BUCKET;
    const pathname = normalizeRoute(url.pathname);

    if (pathname === '/add-product') {
      const body = await parseBody(request);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400);
      }

      const data = body.value;
      const file = body.type === 'formData' ? data.get('image') : null;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const name = String(getBodyValue(data, 'name') || '').trim();
      const category = String(getBodyValue(data, 'category') || '').trim();
      const categoryId = String(getBodyValue(data, 'categoryId') || '').trim();
      const description = String(getBodyValue(data, 'description') || '').trim();
      const price = Number(getBodyValue(data, 'price') || 0);
      const sizes = String(getBodyValue(data, 'sizes') || '')
        .split(',')
        .map((size) => size.trim())
        .filter(Boolean);

      const products = await readCatalog(bucket);
      const product = { id, name, category, categoryId, price, description, sizes, image: '', imageKey: '' };

      if (file && typeof file === 'object' && 'arrayBuffer' in file) {
        const upload = await uploadImage(bucket, env, file, categoryId, id);
        product.image = upload.publicUrl;
        product.imageKey = upload.objectKey;
      }

      products.push(product);
      await writeCatalog(bucket, products);
      return jsonResponse({ success: true, product, products });
    }

    if (pathname === '/edit-product') {
      return jsonResponse({ success: false, error: 'Edit not implemented in this template' }, 501);
    }

    if (pathname === '/delete-product') {
      return jsonResponse({ success: false, error: 'Delete not implemented in this template' }, 501);
    }

    return jsonResponse({ success: false, error: 'Not found' }, 404);
  },
};
